{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE GADTs             #-}
{-# LANGUAGE OverloadedStrings #-}
module Analysis.Netstat (anaNetstat, parseNetstatNA, parseNetstatNAP) where

import           Analysis.Common
import           Analysis.Parsers
import           Analysis.Types

import           Control.Monad
import           Control.Monad.State.Strict as S
import           Data.Maybe                 (catMaybes)
import           Data.Sequence              (Seq)
import qualified Data.Sequence              as Seq
import           Data.Text                  (Text)
import qualified Data.Text                  as T
import           Network.IP.Addr
import           Text.Megaparsec
import           Text.Megaparsec.Char

anaNetstat :: Analyzer (Seq ConfigInfo)
anaNetstat =    (parseNetstatNAP <$> requireTxt ["reseau/netstat-nap.txt"])
            <|> (parseNetstatNA <$> requireTxt ["reseau/netstat-na.txt"]) -- solaris

data SolarisSection = SecUDP4
                    | SecUDP6
                    | SecTCP4
                    | SecTCP6
                    | SecUnk

parseNetstatNA :: Text -> Seq ConfigInfo
parseNetstatNA = Seq.fromList . catMaybes . (\lns -> evalState (mapM (parseLine . T.strip) lns) SecUnk ) . T.lines
    where
        parseLine :: T.Text -> S.State SolarisSection (Maybe ConfigInfo)
        parseLine "UDP: IPv4" = put SecUDP4 >> return Nothing
        parseLine "TCP: IPv4" = put SecTCP4 >> return Nothing
        parseLine "UDP: IPv6" = put SecUDP6 >> return Nothing
        parseLine "TCP: IPv6" = put SecTCP6 >> return Nothing
        parseLine "SCTP:"     = put SecUnk >> return Nothing
        parseLine "" = return Nothing
        parseLine x | "Local Address" `T.isPrefixOf` x = return Nothing
                    | "----" `T.isPrefixOf` x = return Nothing
                    | otherwise = parseLine' x
        parseLine' x = do
            let mklisten cstr i a = case parse (listeningip i) "dummy" a of
                                        Right (ls, prt) -> return $ Just $ CConnection $ IP (cstr ls prt i LISTEN) Nothing
                                        Left _ -> mkerr "Could not parse listening port"
                listeningip i = do
                    ls <- (i <$ string "*") <|> textual
                    void $ char '.'
                    prt <- textual
                    return (ls, prt)
                mkerr s = return $ Just $ ConfigError $ ParsingError "reseau/netstat-na.txt" s (Just x)
            s <- S.get
            case (s, T.words x) of
                (SecUnk, _) -> return Nothing
                (SecUDP4, [a,"Idle"]) -> mklisten UDP (IPv4 anyIP4) a
                (SecUDP4, [_,_]) -> return Nothing
                (SecUDP4, [_,_,_]) -> return Nothing
                (SecUDP4, _) -> mkerr "Bad UDP4 line"
                (SecUDP6, [a,"Idle"]) -> mklisten UDP (IPv6 anyIP6) a
                (SecUDP6, [_,_]) -> return Nothing
                (SecUDP6, _) -> mkerr "Bad UDP6 line"
                (SecTCP4, [a, _, _, _, _, _, "LISTEN"]) -> mklisten TCP (IPv4 anyIP4) a
                (SecTCP4, [a, _, _, _, _, _, "BOUND"]) -> mklisten TCP (IPv4 anyIP4) a
                (SecTCP4, [_, _, _, _, _, _, _]) -> return Nothing
                (SecTCP4, _) -> mkerr "Bad TCP4 line"
                (SecTCP6, [a, _, _, _, _, _, "LISTEN"]) -> mklisten TCP (IPv6 anyIP6) a
                (SecTCP6, [a, _, _, _, _, _, "BOUND"]) -> mklisten TCP (IPv6 anyIP6) a
                (SecTCP6, [_, _, _, _, _, _, _]) -> return Nothing
                (SecTCP6, _) -> mkerr "Bad TCP6 line"


parseNetstatNAP :: Text -> Seq ConfigInfo
parseNetstatNAP t = parseToConfigInfoMT CConnection lns $ map (parse netstateNAPLine "netstat-nap") lns
    where
        lns = filter isCnx $ T.lines t
        isCnx = flip elem ["tcp","udp"] . T.take 3

data DPORT = AnyPort | DP InetPort

ip :: Parser IP
ip = try ipv6 <|> textual

ipv6 :: Parser IP
ipv6 = try (string "::ffff:" *> textual)
     <|> try (string "::1" *> pure (IPv4 loopbackIP4))
     <|> try (string "fe80:") *> parseLinklocal
     <|> try (string "::" *> pure (IPv6 anyIP6))
  where
      parseLinklocal = do
        vals <- some ( try (string ":" *> hexValue <* notFollowedBy (char ' ')) )
        let missingzeroes = 7 - length vals
        case ip6FromWordList (0xfe80 : replicate missingzeroes 0 ++  map fromIntegral vals) of
            Nothing -> fail "Bad ipv6"
            Just v6 -> return (IPv6 v6)


getCnxId :: Parser (IP, InetPort, IP, DPORT)
getCnxId = do
    let parseInt' = parseInt :: Parser Int
    void $ lx parseInt'
    void $ lx parseInt'
    sip <- lx ip
    void $ char ':'
    sport <- lx textual
    dip <- lx ip
    void $ char ':'
    dport <- (AnyPort <$ char '*')
         <|> (DP <$> textual)

    return (sip, sport, dip, dport)

loadProgram :: Parser (Maybe (Int, Text))
loadProgram = Nothing <$ char '-'
       <|> do
           pid <- parseInt
           void $ char '/'
           prg <- T.strip . T.pack <$> some anySingle
           return (Just (pid, prg))

parseTCPNAP :: Parser Connection
parseTCPNAP = do
    (lip, lport, rip, drport) <- lx getCnxId
    let mkDport x = case drport of
                        AnyPort -> fail "This type of connection should have a remote port"
                        DP rport -> pure (x rport)
    stt <- lx (   try (string "LISTEN"      *> pure LISTEN )
              <|> try (string "ESTABLISHED" *> mkDport ESTABLISHED )
              <|> try (string "TIME_WAIT"   *> mkDport TIME_WAIT)
              <|> try (string "CLOSE_WAIT"  *> mkDport CLOSE_WAIT )
              <|> try (string "LAST_ACK"    *> mkDport LAST_ACK )
              <|> try (string "SYN_SENT"    *> mkDport SYN_SENT )
              <|> try (string "FIN_WAIT2"   *> mkDport FIN_WAIT2 )
              )
    IP (TCP lip lport rip stt) <$> loadProgram

parseUDPNAP :: Parser Connection
parseUDPNAP = do
    (lip, lport, rip, drport) <- lx getCnxId
    stt <- optional (lx (string "ESTABLISHED"))
    prg <- loadProgram
    case (stt, drport) of
        (Just _, AnyPort)  -> fail "An established connection should have a remote port"
        (Just _, DP rport) -> return (IP (UDP lip lport rip (ESTABLISHED rport)) prg)
        (Nothing,_)        -> return (IP (UDP lip lport rip LISTEN) prg)

netstateNAPLine :: Parser Connection
netstateNAPLine = do
    p <- lx $ do
      str <- replicateM 3 lowerChar
      void $ optional (char '6')
      return str
    case p of
        "tcp" -> parseTCPNAP
        "udp" -> parseUDPNAP
        _     -> fail ("Unknown protocol " <> p)

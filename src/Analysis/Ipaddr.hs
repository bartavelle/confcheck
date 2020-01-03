{-# LANGUAGE TemplateHaskell #-}
module Analysis.Ipaddr (anaIpaddr) where

import           Analysis.Common
import           Analysis.Parsers
import           Analysis.Types.ConfigInfo
import           Analysis.Types.Helpers     (CError (..))
import           Analysis.Types.Network

import           Control.Lens
import           Control.Monad
import           Data.List                  (foldl')
import           Data.Sequence              (Seq)
import qualified Data.Sequence              as Seq
import           Data.Text                  (Text)
import qualified Data.Text                  as T
import qualified Data.Vector                as V
import           Network.IP.Addr
import           Text.Megaparsec
import           Text.Megaparsec.Char
import           Text.Megaparsec.Char.Lexer (hexadecimal)

data Retrieved
    = Retrieved
    { _itfname  :: Maybe Text
    , _itfaddr4 :: Maybe Net4Addr
    , _itfaddr6 :: Maybe Net6Addr
    , _itfmac   :: Maybe MAC
    } deriving Show

makeLenses ''Retrieved

anaIpaddr :: Analyzer (Seq ConfigInfo)
anaIpaddr = parseIpaddr <$> requireTxt ["reseau/ip-addr.txt"]

emptyRetrieved :: Retrieved
emptyRetrieved = Retrieved Nothing Nothing Nothing Nothing

data LocalState
    = LocalState (Seq ConfigInfo) Retrieved
    deriving Show

parseIpaddr :: Text -> Seq ConfigInfo
parseIpaddr = finalize . foldl' appendInfo (LocalState mempty emptyRetrieved) . T.lines

finalize :: LocalState -> Seq ConfigInfo
finalize (LocalState curseq curretrieved) = curseq <> flushRetrieved curretrieved

flushRetrieved :: Retrieved -> Seq ConfigInfo
flushRetrieved retr =
    case retr of
      Retrieved Nothing Nothing Nothing Nothing -> mempty
      Retrieved Nothing _ _ _ -> Seq.singleton (ConfigError $ MiscError "Could not extract interface name")
      Retrieved (Just iname) _ _ _ -> ip4 iname <> ip6 iname
   where
     mc = retr ^. itfmac
     ip4 iname = maybe mempty (\i -> Seq.singleton $ CIf $ If4 iname i mc) (retr ^. itfaddr4)
     ip6 iname = maybe mempty (\i -> Seq.singleton $ CIf $ If6 iname i mc) (retr ^. itfaddr6)

data LineResult
    = AppendInfo (Retrieved -> Retrieved)
    | NewIf Retrieved
    | Problem (Seq ConfigInfo)

ifaceDesc :: Parser LineResult
ifaceDesc = do
    skipSome digitChar
    void (string ": ")
    nm <- takeWhile1P (Just "ifname") (/= ':')
    void (char ':')
    pure (NewIf (emptyRetrieved & itfname ?~ nm))

ifaceLink :: Parser LineResult
ifaceLink = do
    void $ string "link/ether "
    hdigits <- hexadecimal `sepBy1` char ':'
    pure (AppendInfo (itfmac ?~ MAC (V.fromList hdigits)))

ignoredLine :: Parser LineResult
ignoredLine = AppendInfo id <$ (string "valid_lft" <|> string "link/none" <|> string "link/loopback")

ipv4 :: Parser LineResult
ipv4 = do
    void $ string "inet "
    ipaddr <- try textual <|> (`net4Addr` 32) <$> textual
    pure (AppendInfo (itfaddr4 ?~ ipaddr))

ipv6 :: Parser LineResult
ipv6 = do
    void $ string "inet6 "
    ipaddr <- textual
    pure (AppendInfo (itfaddr6 ?~ ipaddr))

appendInfo :: LocalState -> Text -> LocalState
appendInfo (LocalState curseq curretr) ln =
    case parse (space *> (ifaceDesc <|> ifaceLink <|> ipv4 <|> ipv6 <|> ignoredLine)) "ip addr list" ln of
      Right (AppendInfo f) -> LocalState curseq (f curretr)
      Right (Problem plm) -> LocalState (curseq <> plm) curretr
      Right (NewIf nif) -> LocalState (curseq <> flushRetrieved curretr) nif
      Left rr -> LocalState (curseq <> Seq.singleton (parseErrorToConfigInfo  (Just "ip addr list") rr)) curretr

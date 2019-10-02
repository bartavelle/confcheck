module Analysis.Ifconfig (anaIfconfig) where


import           Analysis.Common
import           Analysis.Types

import           Control.Applicative
import           Control.Lens
import           Control.Monad
import           Data.Attoparsec.Text
import           Data.Bits
import           Data.Char            (isAlphaNum)
import           Data.Maybe           (mapMaybe)
import           Data.Sequence        (Seq)
import qualified Data.Sequence        as Seq
import           Data.Text            (Text)
import qualified Data.Text            as T
import           Data.Textual
import qualified Data.Vector          as V
import           Network.IP.Addr

data IfLineInfo = IfLName Text (Maybe MAC)
                | IfLIP4 Net4Addr
                | IfLIP6 Net6Addr

anaIfconfig :: Analyzer (Seq ConfigInfo)
anaIfconfig = fmap CIf . parseIfconfig <$> requireTxt ["reseau/ifconfig-a.txt"]

parseIfconfig :: Text -> Seq NetIf
parseIfconfig = Seq.fromList . collectInfo . mapMaybe parseIfline . T.lines
    where
        collectInfo (IfLName n mc : IfLIP4 net : xs) = If4 n net mc : collectInfo xs
        collectInfo (IfLName n mc : IfLIP6 net : xs) = If6 n net mc : collectInfo xs
        collectInfo (_ : xs) = collectInfo xs
        collectInfo [] = []

iface :: Parser IfLineInfo
iface = do
    name <- takeWhile1 (\x -> isAlphaNum x || x == '.')
    mac <- optional $ do
        skipSpace
        void $ string "Link encap:Ethernet"
        skipSpace
        void $ string "HWaddr"
        skipSpace
        MAC . V.fromList <$> (hexadecimal `sepBy1` char ':')
    return $ IfLName name mac

linuxIP4 :: Parser IfLineInfo
linuxIP4 = do
    skipSpace
    void $ string "inet ad"
    void (string "r:" <|> string "dr:")
    ip <- textual
    skipWhile (/= ':')
    void $ char ':'
    skipWhile (/= ':')
    void $ char ':'
    maskip <- textual
    let mask = fromIntegral $ popCount (maskip :: IP4)
    return (IfLIP4 (netAddr ip mask) )

solarisIP4 :: Parser IfLineInfo
solarisIP4 = do
    skipSpace
    void $ string "inet "
    ip <- textual
    void $ string " netmask "
    maskip <- hexadecimal
    let mask = fromIntegral $ popCount (maskip :: Int)
    return (IfLIP4 (netAddr ip mask) )

ifline :: Parser IfLineInfo
ifline = iface <|> linuxIP4 <|> solarisIP4

parseIfline :: Text -> Maybe IfLineInfo
parseIfline = preview _Right . parseOnly ifline

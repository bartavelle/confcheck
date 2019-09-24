{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Prelude

import qualified Data.ByteString              as  BS
import qualified Data.ByteString.Lazy         as  BSL
import qualified Data.Conduit.Binary          as  CB
import           Control.Monad.Trans.Resource (runResourceT)
import qualified Data.HashMap.Strict          as  HM
import qualified Data.Serialize               as  S
import qualified Data.Map.Strict              as  M
import qualified Data.Text                    as  T
import qualified Data.Text.Read               as  T
import qualified Data.Vector                  as  V
import           Network.HTTP.Simple
import           Network.HTTP.Types.Status    (Status(..))
import qualified Text.XML                     as  XML

import Control.Lens
import Text.XML.Stream.Parse hiding (attr)
import Text.XML.Lens
import Control.Monad
import Data.Csv
import Data.CaseInsensitive (mk)
import Data.Maybe
import Data.String (IsString)
import Data.Time (getZonedTime, ZonedTime(..), LocalTime(..), toGregorian, fromGregorian, Day)
import Development.Shake
import Development.Shake.FilePath
import System.Directory (createDirectoryIfMissing)

import Analysis.Types
import Analysis.Common
import Analysis.Oval
import Data.Oval

lNode :: T.Text -> Traversal' Element Element
lNode t = nodes . traverse . _Element . named (mk t)

data KBDate = KBDate { _kbdPosted      :: Day
                     , _kbdBulletinKB  :: Maybe Int
                     , _kbdComponentKB :: Maybe Int
                     , _kbdBulletinID  :: T.Text
                     } deriving Show

instance FromNamedRecord KBDate where
    parseNamedRecord m = KBDate <$> (m .: "Date Posted" >>= getDay)
                                <*> (m .: "Bulletin KB"  >>= mgetInt)
                                <*> (m .: "Component KB" >>= mgetInt)
                                <*> (m .: "Bulletin Id")
        where
            getDay t = case mapM text2Int (T.splitOn "/" t) of
                           Just [d,mn,ye] -> pure (fromGregorian (fromIntegral ye) mn d)
                           _ -> fail "Can't convert day"
            getInt :: T.Text -> Parser Int
            getInt = maybe (fail "Can't convert KB") pure . text2Int
            mgetInt :: T.Text -> Parser (Maybe Int)
            mgetInt t | T.null t = pure Nothing
                      | otherwise = Just <$> getInt t

loadMicrosoftBulletin :: FilePath -> IO (Either String [KBDate])
loadMicrosoftBulletin fp = (_Right %~ V.toList . snd) . decodeByName <$> BSL.readFile fp

loadYear :: FilePath -> IO (M.Map T.Text (Day, Severity))
loadYear = fmap (M.fromList . extractCVE) . XML.readFile def
  where
    extractCVE = toListOf (root . nodes . traverse . _Element . to mkCVE)
    mkCVE e = (e ^. attr "id", (parseDate (e ^. lNode "published-datetime" . text) , e ^. lNode "cvss" . lNode "base_metrics" . lNode "score" . text . to readScore))
    parseDate x = case T.splitOn "-" (T.takeWhile (/='T') x) of
                      [y,m,d] -> fromGregorian (fromIntegral (g y)) (g m) (g d)
                      _ -> fromGregorian 1970 1 1
    readScore t = case T.double t of
                      Right (v, "") -> CVSS v
                      _ -> Unknown
    g :: T.Text -> Int
    g = read . T.unpack

data RCompr
  = BZip2
  | GZip
  | NoCompression
  deriving (Show, Eq, Enum, Ord, Bounded)

extension :: IsString s => RCompr -> s
extension c =
    case c of
      BZip2         -> ".bz2"
      GZip          -> ".gz"
      NoCompression -> ""

data DlSource
    = DL
    { _urlUrl         :: String
    , _urlCompression :: RCompr
    , _urlFilename    :: FilePath
    , _dlEnrich       :: Bool
    } deriving Show

ovalSources :: [DlSource]
ovalSources =
    [ DL "http://support.novell.com/security/oval"            NoCompression "suse.linux.enterprise.server.11.xml" True
    , DL "http://www.redhat.com/security/data/oval"           BZip2         "com.redhat.rhsa-all.xml"             False
    , DL "http://support.novell.com/security/oval"            NoCompression "opensuse.12.2.xml"                   True
    , DL "http://support.novell.com/security/oval"            NoCompression "opensuse.12.3.xml"                   True
    , DL "http://support.novell.com/security/oval"            NoCompression "opensuse.13.2.xml"                   True
    , DL "http://support.novell.com/security/oval"            NoCompression "opensuse.13.1.xml"                   True
    , DL "https://www.debian.org/security/oval"               NoCompression "oval-definitions-buster.xml"         False
    , DL "https://www.debian.org/security/oval"               NoCompression "oval-definitions-jessie.xml"         False
    , DL "https://www.debian.org/security/oval"               NoCompression "oval-definitions-stretch.xml"        False
    , DL "https://www.debian.org/security/oval"               NoCompression "oval-definitions-wheezy.xml"         False
    , DL "https://people.canonical.com/~ubuntu-security/oval" NoCompression "com.ubuntu.trusty.cve.oval.xml"      False
    , DL "https://people.canonical.com/~ubuntu-security/oval" NoCompression "com.ubuntu.xenial.cve.oval.xml"      False
    ]

downloadSource :: DlSource -> Action ()
downloadSource src = do
  let compression = _urlCompression src
      fullname = _urlFilename src <> extension compression
      fullurl = _urlUrl src <> "/" <> fullname
      compressedname = "sources/" <> fullname
  join $ liftIO $ do
    req <- setRequestIgnoreStatus <$> parseRequest fullurl
    runResourceT $ httpSink req $ \res ->
      case getResponseStatus res of
        Status 200 _ -> pure () <$ CB.sinkFile compressedname
        s -> pure (fail (show s))
  case compression of
    NoCompression -> pure ()
    GZip -> command_ [] "gunzip" [compressedname]
    BZip2 -> command_ [] "bunzip2" [compressedname]

loadSources :: Integer -> Rules ()
loadSources year = do
  let dl src = ("sources" </> _urlFilename src) %> \_ -> downloadSource src
  -- downloading CVEs
  forM_ [2002..year] $ \y ->
    let yt = show y
        filename = "nvdcve-2.0-" <> yt <> ".xml"
    in  dl (DL "http://static.nvd.nist.gov/feeds/xml/cve" GZip filename False)
  -- downloading various stuff
  dl (DL "https://getupdates.oracle.com/reports" NoCompression "patchdiag.xref" False)
  -- downloading ovals
  forM_ ovalSources dl

loadCVEs :: FilePath -> Action (M.Map T.Text (Day, Severity))
loadCVEs f =
  (S.decode <$> liftIO (BS.readFile f))
    >>= either fail pure


main :: IO ()
main = do
  createDirectoryIfMissing False "serialized"
  createDirectoryIfMissing False "sources"
  ZonedTime (LocalTime today _) _ <- getZonedTime
  let (currentYear, _, _) = toGregorian today
  shakeArgs shakeOptions $ do
    want $ do
      e <- [ "cve.cereal"
           , "BulletinSearch.serialized"
           ] ++ map _urlFilename ovalSources
      pure ("serialized/" <> e)
    want ["sources/patchdiag.xref"]
    loadSources currentYear
    "sources/BulletinSearch.csv" %> \out -> do
      e <- doesFileExist out
      unless e $ fail $ unlines
        [ "You need to download BulletinSearch.xlsx from Microsoft."
        , "  * https://www.microsoft.com/en-us/download/details.aspx?id=36982"
        , "Once downloaded, convert it to csv and save it to " <> out
        ]
    "serialized/cve.cereal" %> \out -> do
      let pathes = [ "serialized/nvdcve-2.0-" <> show year <> ".xml" | year <- [2002..currentYear] ]
      need pathes
      cves <- mconcat <$> mapM loadCVEs pathes
      liftIO (BS.writeFile out (S.encode cves))
    "serialized/nvdcve-2.0-*.xml" %> \out -> do
      let src = "sources" </> dropDirectory1 out
      liftIO (putStrLn src)
      need [src]
      cnt <- liftIO (loadYear src)
      liftIO (BS.writeFile out (S.encode cnt))
    "serialized/BulletinSearch.serialized" %> \out -> do
      need ["sources/BulletinSearch.csv"]
      l <- liftIO (loadMicrosoftBulletin "sources/BulletinSearch.csv")
      case l of
          -- sérialisé sous forme [(Int, Text, Day)]
          Right kbdates -> let kblist = concatMap (\(KBDate d k1 k2 t) -> map (fmap (,t,d)) [k1,k2]) kbdates
                               lst :: [(Int, T.Text, Day)]
                               lst = catMaybes kblist
                           in  liftIO (BS.writeFile out (S.encode lst))
          Left rr -> fail rr
    mapM_ serializeOval ovalSources

serializeOval :: DlSource -> Rules ()
serializeOval src =
  let filename = _urlFilename src
  in  ("serialized" </> filename) %> \out -> do
        let srcname = "sources" </> filename
        need [srcname, "serialized/cve.cereal"]
        (oval, tests) <- liftIO (parseOvalFile srcname) >>= either fail pure
        eoval <-
          if _dlEnrich src
            then do
              cves <- loadCVEs "serialized/cve.cereal"
              pure (enrichOval cves oval)
            else pure oval
        liftIO (BS.writeFile out (S.encode (eoval, HM.toList tests)))


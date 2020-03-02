{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE TupleSections     #-}
module Main (main) where

import           Prelude

import           Control.Lens
import           Control.Monad
import           Control.Monad.Trans.Resource (runResourceT)
import           Data.Aeson.Lens
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Lazy         as BSL
import qualified Data.Conduit.Binary          as CB
import           Data.Csv
import qualified Data.HashMap.Strict          as HM
import qualified Data.Map.Strict              as M
import           Data.Maybe
import qualified Data.Serialize               as S
import           Data.String                  (IsString)
import qualified Data.Text                    as T
import           Data.Time                    (Day, LocalTime (..),
                                               ZonedTime (..), fromGregorian,
                                               getZonedTime, toGregorian)
import           Data.Time.Clock              (UTCTime (..))
import qualified Data.Vector                  as V
import           Development.Shake
import           Development.Shake.FilePath
import           Network.HTTP.Simple
import           Network.HTTP.Types.Status    (Status (..))
import           System.Directory             (createDirectoryIfMissing)

import           Analysis.Common
import           Analysis.Oval
import           Analysis.Types.Vulnerability
import           Data.Oval

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
loadYear fp = do
    filecontent <- BS.readFile fp
    let cves = filecontent ^.. key "CVE_Items" . _Array . traverse
        mkcve cve = case extract cve of
                      ( Just cveid, Just pubdate, sev) ->
                        case sev of
                          Just "HIGH"   -> (cveid, (utctDay pubdate, High))
                          Just "MEDIUM" -> (cveid, (utctDay pubdate, Medium))
                          Just "LOW"    -> (cveid, (utctDay pubdate, Low))
                          Just sev'     -> error ("Unknown severity: " ++ show sev')
                          Nothing       -> (cveid, (utctDay pubdate, Unknown))
                      ex                -> error ("Invalid cve entry: " ++ show ex)
        extract cve =
          ( cve ^? key "cve" . key "CVE_data_meta" . key "ID" . _String
          , cve ^? key "publishedDate" . _JSON
          , cve ^? key "impact" . key "baseMetricV2" . key "severity" . _String
          )


    pure (M.fromList (map mkcve cves))

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
    , DL "http://support.novell.com/security/oval"            NoCompression "suse.linux.enterprise.server.12.xml" True
    , DL "http://support.novell.com/security/oval"            NoCompression "suse.linux.enterprise.server.15.xml" True
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
    , DL "https://people.canonical.com/~ubuntu-security/oval" NoCompression "com.ubuntu.bionic.cve.oval.xml"      False
    , DL "http://support.novell.com/security/oval"            NoCompression "opensuse.leap.15.0.xml"              True
    , DL "http://support.novell.com/security/oval"            NoCompression "opensuse.leap.15.1.xml"              True
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
        s            -> pure (fail (show s))
  case compression of
    NoCompression -> pure ()
    GZip          -> command_ [] "gunzip" [compressedname]
    BZip2         -> command_ [] "bunzip2" [compressedname]

loadSources :: Integer -> Rules ()
loadSources year = do
  let dl src = ("sources" </> _urlFilename src) %> \_ -> downloadSource src
  -- downloading CVEs
  forM_ [2002..year] $ \y ->
    let yt = show y
        filename = "nvdcve-1.1-" <> yt <> ".json"
    in  dl (DL "https://nvd.nist.gov/feeds/json/cve/1.1/" GZip filename False)
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
      let pathes = [ "serialized/nvdcve-1.1-" <> show year <> ".json" | year <- [2002..currentYear] ]
      need pathes
      cves <- mconcat <$> mapM loadCVEs pathes
      liftIO (BS.writeFile out (S.encode cves))
    "serialized/nvdcve-1.1-*.json" %> \out -> do
      let src = "sources" </> dropDirectory1 out
      liftIO (putStrLn src)
      need [src]
      cnt <- liftIO (loadYear src)
      liftIO (BS.writeFile out (S.encode cnt))
    "serialized/BulletinSearch.serialized" %> \out -> do
      need ["sources/BulletinSearch.csv"]
      need ["sources/BulletinSearch2001-2008.csv"]
      l <- liftIO (loadMicrosoftBulletin "sources/BulletinSearch.csv")
      lOld <- liftIO (loadMicrosoftBulletin "sources/BulletinSearch.csv")
      case (<>) <$> l <*> lOld of
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

{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Prelude
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Serialize as S
import qualified Data.Map.Strict as M
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.Text.Read as T
import qualified Data.HashMap.Strict as HM
import qualified Text.XML as XML
import Control.Lens
import Text.XML.Stream.Parse hiding (attr)
import Text.XML.Lens
import Data.Time
import Data.String
import System.IO
import Control.Monad
import Data.List
import Data.Maybe
import System.Directory
import Data.Csv
import Data.CaseInsensitive (mk)
import Control.Concurrent.ParallelIO (parallel)
import Control.DeepSeq (deepseq)
import System.Environment
import Data.Time (getZonedTime, ZonedTime(..), LocalTime(..), toGregorian)

import Analysis.Types
import Analysis.Common
import Analysis.Oval
import Analysis.Debian
import Data.Oval

cveserial :: FilePath
cveserial = "serialized/cve.cereal"

lNode :: T.Text -> Traversal' Element Element
lNode t = nodes . traverse . _Element . named (mk t)


loadCVE :: FilePath -> IO (M.Map T.Text (Day, Severity))
loadCVE sourcedir = do
      ZonedTime (LocalTime today _) _ <- getZonedTime
      let (currentYear, _, _) = toGregorian today
      M.fromList . concat <$> parallel (map loadCVE' [2002..currentYear])
    where
        loadCVE' y = do
            o <- extractCVE <$> loadYear y
            o `deepseq` hPutStrLn stderr ("Loading CVSS for year " <> show y)
            return o
        loadYear :: Integer -> IO Document
        loadYear year = XML.readFile def (fromString (sourcedir <> "/nvdcve-2.0-" <> show year <> ".xml"))
        readScore t = case T.double t of
                          Right (v, "") -> CVSS v
                          _ -> Unknown
        extractCVE = toListOf (root . nodes . traverse . _Element . to mkCVE)
        mkCVE e = (e ^. attr "id", (parseDate (e ^. lNode "published-datetime" . text) , e ^. lNode "cvss" . lNode "base_metrics" . lNode "score" . text . to readScore))
        g :: T.Text -> Int
        g = read . T.unpack
        parseDate x = case T.splitOn "-" (T.takeWhile (/='T') x) of
                          [y,m,d] -> fromGregorian (fromIntegral (g y)) (g m) (g d)
                          _ -> fromGregorian 1970 1 1

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

main :: IO ()
main = do
    args <- getArgs
    if null args
      then mainF
      else undefined

mainF :: IO ()
mainF = do
    let sourcedir = "source"
        serialdir = "serialized"
    exists <- doesFileExist cveserial
    cves <- if exists
                then loadSerializedCVE cveserial
                else do
                    putStrLn "Serializing cve data"
                    r <- loadCVE sourcedir
                    BS.writeFile cveserial (S.encode r)
                    return r
    BS.writeFile (serialdir <> "/cve.cereal") (S.encode cves)
    putStrLn "Serializing KB dates"
    l <- loadMicrosoftBulletin (sourcedir <> "/BulletinSearch.csv")
    case l of
        -- sérialisé sous forme [(Int, Text, Day)]
        Right kbdates -> let kblist = concatMap (\(KBDate d k1 k2 t) -> map (fmap (,t,d)) [k1,k2]) kbdates
                             lst :: [(Int, T.Text, Day)]
                             lst = catMaybes kblist
                         in  BS.writeFile (serialdir <> "/BulletinSearch.serialized") (S.encode lst)
        Left rr -> error rr

    forM_ [ "com.redhat.rhsa-all.xml"
          , "oval-definitions-buster.xml"
          , "oval-definitions-jessie.xml"
          , "oval-definitions-stretch.xml"
          , "oval-definitions-wheezy.xml"
          , "com.ubuntu.trusty.cve.oval.xml"
          , "com.ubuntu.xenial.cve.oval.xml"
          , "suse.linux.enterprise.server.11.xml"
          , "opensuse.12.2.xml"
          , "opensuse.12.3.xml"
          , "opensuse.13.2.xml"
          , "opensuse.13.1.xml"
          ] $ \f -> do
        putStrLn ("Serializing " ++ f)
        (oval, tests) <- parseOvalFile (fromString (sourcedir <> "/" <> f)) >>= either error pure
        let eoval | "suse.linux" `isPrefixOf` f = enrichOval cves oval
                  | "opensuse."  `isPrefixOf` f = enrichOval cves oval
                  | otherwise = oval
        BS.writeFile (serialdir ++ "/" ++ f) (S.encode (eoval, HM.toList tests))


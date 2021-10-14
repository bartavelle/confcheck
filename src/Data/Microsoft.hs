{-# LANGUAGE OverloadedStrings #-}

module Data.Microsoft
  ( analyzeMBSA,
    analyzeMBSAContent,
    analyzeMissingKBs,
    analyzeMissingKBsContent,
    MBSA (..),
    mbsa,
    loadKBDays,
  )
where

import Analysis.Common
import Analysis.Types.ConfigInfo
import Analysis.Types.Helpers (CError (..))
import Analysis.Types.Vulnerability
import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.IntMap.Strict as IM
import Data.Parsers.Xml
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import qualified Data.Serialize as S
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Textual as T
import Data.Time

data MBSA
  = MBSA
      { _mbsaId :: Text,
        _mbsaKBID :: Int,
        _mbsaTitle :: Text,
        _mbsaBURL :: Maybe Text,
        _mbsaIURL :: Maybe Text,
        _mbsaOIDS :: [(Text, Text)],
        _mbsaInstalled :: Bool,
        _mbsaSev :: Severity
      }
  deriving (Show)

loadKBDays :: FilePath -> IO (IM.IntMap (T.Text, Day))
loadKBDays = BS.readFile >=> either error (pure . IM.fromList . map (\(kb, t, d) -> (kb, (t, d)))) . S.decode

mkerr :: FilePath -> String -> Seq Vulnerability
mkerr fp rr = Seq.singleton (ConfigInformation (ConfigError (MiscError ("Something went wrong when analyzing " <> T.pack fp <> ": " <> T.pack rr))))

findKBInfo :: Int -> IM.IntMap (T.Text, Day) -> (T.Text, Day)
findKBInfo = IM.findWithDefault ("?", epoch)
  where
    epoch = fromGregorian 1970 1 1

analyzeMBSAContent :: Once (IM.IntMap (T.Text, Day)) -> FilePath -> BS.ByteString -> IO (Seq Vulnerability)
analyzeMBSAContent ody fp content = either (mkerr fp) Seq.fromList <$> (analyzeMBSA' <$> getOnce ody)
  where
    analyzeMBSA' :: IM.IntMap (T.Text, Day) -> Either String [Vulnerability]
    analyzeMBSA' mp = fmap (map toVulnerability . filter missing) parsed
      where
        parsed = parseStream "mbsa.xml" (BSL.fromChunks [content]) mbsa
        toVulnerability (MBSA mid mkb mtitle _ _ _ _ sev) =
          let (bulletinid, day) = findKBInfo mkb mp
              miss = MP (mid <> "/KB" <> T.toText mkb) day (Just (bulletinid <> " " <> mtitle))
           in Vulnerability sev (MissingPatch miss)

analyzeMBSA :: Once (IM.IntMap (T.Text, Day)) -> FilePath -> IO (Seq Vulnerability)
analyzeMBSA ody fp = BS.readFile fp >>= analyzeMBSAContent ody fp

analyzeMissingKBs :: Once (IM.IntMap (T.Text, Day)) -> FilePath -> IO (Seq Vulnerability)
analyzeMissingKBs ody fp =
  BS.readFile fp >>= analyzeMissingKBsContent ody fp

analyzeMissingKBsContent :: Once (IM.IntMap (T.Text, Day)) -> FilePath -> BS.ByteString -> IO (Seq Vulnerability)
analyzeMissingKBsContent ody fp filecontent = do
  mp <- getOnce ody
  let toVulnerability ln = case T.splitOn "(KB" ln of
        [mtitle, rest] -> case T.break (== ')') rest of
          (_, "") -> Left ("Bad line (no closing parens): " ++ show ln)
          (tkb, rest') -> case T.splitOn "\t" rest' of
            (_ : tcrit : _) -> toVulnerability' ln mtitle tkb tcrit
            _ -> Left ("Bad line (no crit): " ++ show ln)
        _ -> Left ("Bad line (no KB split): " ++ show ln)
      toVulnerability' ln mtitle tkb tcrit = do
        let title = T.strip mtitle
        nkb <- maybe (Left ("Bad KB " ++ show ln)) Right $ T.fromText tkb
        let crit = case tcrit of
              "Critical" -> CVSS 10
              "Important" -> High
              "Moderate" -> Medium
              "Low" -> Low
              _ -> None
            (bulletinid, day) = findKBInfo nkb mp
        let miss = MP ("KB" <> tkb) day (Just (bulletinid <> " " <> title))
        return $ Vulnerability crit $ MissingPatch miss
      mresult = mapM toVulnerability . filter (T.isInfixOf "(KB") . T.lines
  let decodefunction =
        if "\255\254" `BS.isPrefixOf` filecontent
          then T.decodeUtf16LE
          else T.decodeLatin1
      textcontent = decodefunction filecontent
  return (either (mkerr fp) Seq.fromList (mresult textcontent))

missing :: MBSA -> Bool
missing = not . _mbsaInstalled

mbsa :: Parser [MBSA]
mbsa = fmap concat $ element_ "XMLOut" $ some (try cataloginfo <|> mcategory)
  where
    mcategory = lx checkCategory
    cataloginfo = const [] <$> lx (ignoreElement "CatalogInfo")

checkCategory :: Parser [MBSA]
checkCategory = element_ "Check" $ do
  lx $ ignoreElement "Advice"
  lx (element_ "Detail" (many updatedata) <|> return [])

rBool :: Text -> Parser Bool
rBool "true" = pure True
rBool "false" = pure False
rBool x = fail (show x <> " is not a boolean")

rSev :: Text -> Parser Severity
rSev "0" = pure None
rSev "1" = pure Low
rSev "2" = pure Medium
rSev "3" = pure High
rSev "4" = pure (CVSS 10)
rSev x = fail (show x <> " is an invalid severity")

updatedata :: Parser MBSA
updatedata = lx $ element "UpdateData" $ \mp -> do
  mid <- extractParameter "ID" mp
  rkbid <- extractParameter "KBID" mp
  kbid <- maybe (fail "Can't convert KBID") return (text2Int rkbid)
  title <- lx $ getTextFrom "Title"
  constr <- lx $ element_ "References" $ do
    burl <- lx $ optional $ getTextFrom "BulletinURL"
    iurl <- lx $ optional $ getTextFrom "InformationURL"
    lx $ ignoreElement "DownloadURL"
    return (MBSA mid kbid title burl iurl)
  let oid = element "OtherID" $ \mp' ->
        (,) <$> extractParameter "Type" mp'
          <*> (mconcat <$> some characterdata)
  constr <$> lx (element_ "OtherIDs" (some (lx oid)) <|> return [])
    <*> (extractParameter "IsInstalled" mp >>= rBool)
    <*> (extractParameter "Severity" mp >>= rSev)

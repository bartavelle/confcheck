{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
module Analyzis.Debian (listDebs, DebInfo, postDebAnalyzis, loadDebVulns, loadSerializedCVE) where

import Prelude
import Analyzis.Common
import Analyzis.Types
import Analyzis.Parsers
import Analyzis.Oval (ovalRuleMatchedDEB)
import Data.Oval

import Text.Parser.Token
import Text.Parser.Char
import Text.Parser.Combinators
import Text.Parsec.Text
import Text.Parsec.Prim (parse)
import Data.List.Split (splitWhen)
import Data.Maybe (mapMaybe)
import qualified Data.Map.Strict as M
import qualified Data.Text as T
import qualified Data.Text.IO as T
import qualified Data.Text.Lazy.Builder as TB
import qualified Data.Text.Lazy.Builder.Int as TB
import qualified Data.ByteString as BS
import qualified Data.Serialize as S
import Control.Lens
import Control.Monad
import Control.Applicative
import Data.Monoid
import Data.Sequence (Seq)
import Data.Text (Text)
import qualified Data.HashMap.Strict as HM
import qualified Data.Sequence as Seq
import Data.Char
import Data.Time.Calendar
import Data.Hashable
import Data.DebianVersion

newtype DebInfo = DebInfo (HM.HashMap (DebRelease, Text) [DebianPatch])
                  deriving Show

data DebianPatch = DebianPatch { _dpatchName         :: Text
                               , _dpatchRelease      :: Day
                               , _dpatchCVEs         :: [(Integer, Integer)]
                               , _dpatchFixedVersion :: Maybe DebianVersion
                               , _dpatchSeverity     :: Severity
                               } deriving Show

newtype DebRelease = DebRelease Int
                     deriving (Show, Eq, Ord, Num, Hashable)

data PatchInfo =  PatchInfo DebRelease
                            Text
                            (Maybe DebianVersion)
               deriving Show

data DSA = DSA { _dsaDate    :: Day
               , _dsaName    :: Text
               , _dsaPackage :: Text
               , _dsaCVEs    :: [(Integer, Integer)]
               , _dsaPatch   :: [PatchInfo]
               } deriving Show

data Stuff = SC [(Integer, Integer)]
           | NT
           | PA (Maybe PatchInfo)

makePrisms ''Stuff

loadSerializedCVE :: FilePath -> IO (M.Map T.Text (Day, Severity))
loadSerializedCVE cveserial = do
    f <- BS.readFile cveserial
    case S.decode f of
        Right x -> return x
        Left rr -> error ("Error loading serialized CVE from " <> cveserial <> " " <> rr)

mkdebmap :: Seq ConfigInfo -> M.Map T.Text (T.Text, DebianVersion)
mkdebmap = M.fromList . toListOf (folded . _SoftwarePackage . to dpkg . folded)
  where
    dpkg (Package p v (PDeb srcname _)) = (srcname,) . (p,) <$> either (const Nothing) Just (parseDebianVersion v)
    dpkg _ = Nothing


runOvalAnalyze :: UnixVersion
               -> T.Text -- architecture
               -> M.Map T.Text (T.Text, DebianVersion)
               -> ([OvalDefinition], HM.HashMap OTestId OFullTest)
               -> Seq Vulnerability
runOvalAnalyze uv arch sourcemap (ovs, tests) = do
    let packagemap = M.fromList (M.elems sourcemap)
    ov@(OvalDefinition _ t _ d _ sev _ day) <- Seq.fromList ovs
    let (matched, pkgs) = ovalRuleMatchedDEB uv arch sourcemap tests ov
    guard matched
    (pkg, correctver) <- Seq.fromList pkgs
    let mvulnver = packagemap ^? ix pkg
        vshow = T.pack . show . prettyDebianVersion
    case mvulnver of
      Nothing -> return $ Vulnerability sev $ OutdatedPackage pkg "zozo" (vshow correctver) day (Just (t <> "\n" <> d))
      Just vulnver -> return $ Vulnerability sev $ OutdatedPackage pkg (vshow vulnver) (vshow correctver) day (Just (t <> "\n" <> d))

postDebAnalyzis :: (UnixVersion -> Maybe (Once ([OvalDefinition], HM.HashMap OTestId OFullTest)))
                -> Once (Either CError DebInfo)
                -> Seq ConfigInfo
                -> IO (Seq Vulnerability)
postDebAnalyzis oval info ce = do
    let tolst (Left rr) = [ConfigInformation (ConfigError rr)]
        tolst (Right x) = analyzis x
        ve = extractVersion ce
        analyzis (DebInfo mp) = case ve of
                                    Just (UnixVersion Debian (n:_)) -> concatMap (runAnalyzis mp (fromIntegral n)) (getDebs ce)
                                    _ -> []
    deb <- Seq.fromList . tolst <$> getOnce info
    ovl <- maybe (pure mempty) (\(v, arch, ov) -> runOvalAnalyze v arch (mkdebmap ce) <$> getOnce ov) $ do
          v <- ve
          ov <- oval v
          arch <- extractArch ce
          return (v,arch,ov)
    return (deb <> ovl)


-- | This analysis is using the old debian-security data from CVS
runAnalyzis :: HM.HashMap (DebRelease, Text) [DebianPatch]
            -> DebRelease
            -> (Text, Text, Maybe Text, DebianVersion)
            -> [Vulnerability]
runAnalyzis mp release (package, sourcepackage, _, packageversion) = do
    DebianPatch dsaname day cves fixedversion sev <- mp ^.. ix (release, sourcepackage) . folded
    let mkvuln v = pure $ Vulnerability sev (OutdatedPackage package (showver packageversion) v day (Just desc))
        desc = T.intercalate " " (dsaname : map showcve cves)
        showcve (y,n) = TB.toLazyText ("CVE-" <> TB.decimal y <> "-" <> TB.decimal n) ^. strict
        showver = T.pack . version
    case fixedversion of
        Nothing -> mkvuln "NO FIX!"
        Just v -> do
            guard (packageversion < v)
            mkvuln (showver v)

mparseDebianVersion :: Text -> Maybe DebianVersion
mparseDebianVersion = either (const Nothing) Just . parseDebianVersion

getDebs :: Seq ConfigInfo -> [(Text, Text, Maybe Text, DebianVersion)]
getDebs = toListOf (folded . _SoftwarePackage . to todeb . folded)
    where
        todeb :: SoftwarePackage -> Maybe (Text, Text, Maybe Text, DebianVersion)
        todeb (Package p v (PDeb s sv)) = fmap (p, s, sv,) (mparseDebianVersion v)
        todeb _ = Nothing

loadDebVulns :: FilePath -> FilePath -> IO (Either CError DebInfo)
loadDebVulns cves f = do
    cvedata <- loadSerializedCVE cves
    (_Left %~ parseErrorToCError) . parse (myparser cvedata) f <$> T.readFile f

dsaToMap :: M.Map T.Text (Day, Severity) -> [DSA] -> HM.HashMap (DebRelease, Text) [DebianPatch]
dsaToMap cvedata = HM.fromListWith (<>) . concatMap formatPatch
    where
        formatPatch (DSA day name _ cves patches) = do
            PatchInfo release package ver <- patches
            let crit (year, nb) = snd $ M.findWithDefault (undefined, Unknown) (T.pack ("CVE-" <> show year <> "-" <> show nb)) cvedata
                maxcrit | null cves = Low
                        | otherwise = maximum (map crit cves)
            return ( (release, package) , [DebianPatch name day cves ver maxcrit] )

myparser :: M.Map T.Text (Day, Severity) -> Parser DebInfo
myparser cvedata = DebInfo . dsaToMap cvedata <$> (many dsa <* eof)

cve :: Parser (Integer, Integer)
cve = token $ do
    void $ string "CVE-"
    y <- decimal
    void $ char '-'
    n <- decimal
    pure (y,n)

parseDistrib :: Parser DebRelease
parseDistrib = some (satisfy isAsciiLower) >>= \v -> case v of
                                                         "stretch" -> pure 9
                                                         "jessie"  -> pure 8
                                                         "wheezy"  -> pure 7
                                                         "squeeze" -> pure 6
                                                         "lenny"   -> pure 5
                                                         "etch"    -> pure 4
                                                         "sarge"   -> pure 3
                                                         "woody"   -> pure 3
                                                         _         -> fail ("Unknown version " <> v)

tol :: Parser ()
tol = skipMany (satisfy (/= '\n')) *> spaces

patchInfo :: Parser (Maybe PatchInfo)
patchInfo = try $ do
    dis <- brackets parseDistrib
    void $ symbolic '-'
    package <- token $ some (satisfy (not . isSpace))
    notaff <- optional (try $ string "<not-affected>")
    eol    <- optional (try $ string "<end-of-life>")
    if has _Nothing notaff && has _Nothing eol
        then do
            ver <-  (string "<unfixed>" *> pure Nothing)
                 <|> fmap Just (some (satisfy (not . isSpace)))
            tol
            pure $ Just $ PatchInfo dis (T.pack package) (ver >>= mparseDebianVersion . T.pack)
        else tol *> pure Nothing

dsa :: Parser DSA
dsa = do
    date <- brackets $ do
        d <- fromInteger <$> token decimal
        m <- token parseEnglishMonth
        y <- token decimal
        pure (fromGregorian y m d)
    mdsa <- token $ some (satisfy (\x -> isAsciiUpper x || x == '-' || isDigit x))
    package <- token $ some (satisfy (not . isSpace))
    void tol
    let note = try (string "NOTE") *> tol
    details <- many (   (SC <$> token (braces (many cve)))
                    <|> (note *> pure NT)
                    <|> (PA <$> token patchInfo)
                    )
    let cves = details ^.. folded . _SC . folded
        ptch = details ^.. folded . _PA . folded
    pure $ DSA date (T.pack mdsa) (T.pack package) cves ptch

parseDpkgStatus :: Text -> [SoftwarePackage]
parseDpkgStatus = mapMaybe (mkPackage . mkmaps) . splitWhen T.null . regroupMultilines . T.lines
    where
        mkPackage m = do
            nm <- m ^? ix "Package"
            ver <- m ^? ix "Version"
            asrc <- m ^? ix "Source"
            st <- m ^? ix "Status"
            guard (st == "install ok installed")
            (src, srcver) <- case T.break (\x -> not (isAlphaNum x || x `elem` ("-.+" :: String))) asrc of
                                 (a, "") -> pure (a, Nothing)
                                 (a, b) -> (a,) . Just <$> (T.stripPrefix "(" (T.strip b) >>= T.stripSuffix ")")
            pure $ Package nm ver (PDeb src srcver)
        regroupMultilines (a : b : xs) | T.null b = a : b : regroupMultilines xs
                                       | T.head b == ' ' = regroupMultilines (a <> b : xs)
        regroupMultilines x = x
        mkmaps :: [Text] -> HM.HashMap Text Text
        mkmaps = HM.fromList . map ((_2 %~ T.drop 2) . T.breakOn ": ")

listDebs :: Analyzer (Seq ConfigInfo)
listDebs = Seq.fromList . fmap SoftwarePackage . parseDpkgStatus <$> requireTxt ["logiciels/dpkg-status"]


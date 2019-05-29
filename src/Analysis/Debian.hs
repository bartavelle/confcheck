{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
module Analysis.Debian (listDebs, postDebAnalysis, loadSerializedCVE) where

import Prelude
import Analysis.Common
import Analysis.Types
import Analysis.Oval (ovalRuleMatchedDEB)
import Data.Oval

import Data.List.Split (splitWhen)
import Data.Maybe (mapMaybe)
import qualified Data.Map.Strict as M
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.Serialize as S
import Control.Lens
import Control.Monad
import Data.Sequence (Seq)
import Data.Text (Text)
import qualified Data.HashMap.Strict as HM
import qualified Data.Sequence as Seq
import Data.Char
import Data.Time.Calendar
import Data.DebianVersion

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

postDebAnalysis :: (UnixVersion -> Maybe (Once ([OvalDefinition], HM.HashMap OTestId OFullTest)))
                -> Seq ConfigInfo
                -> IO (Seq Vulnerability)
postDebAnalysis oval ce =
    maybe (pure mempty) (\(v, arch, ov) -> runOvalAnalyze v arch (mkdebmap ce) <$> getOnce ov) $ do
      v <- extractVersion ce
      ov <- oval v
      arch <- extractArch ce
      return (v,arch,ov)


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


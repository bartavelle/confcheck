{-# LANGUAGE OverloadedStrings #-}

module Analysis.RPM
  ( listRPMs,
    postRPMAnalysis,
    runAnalyze,
    rpmInfos,
    mkrpmmap,
  )
where

import Analysis.Common
import Analysis.Oval
import Analysis.Types.ConfigInfo
import Analysis.Types.Package
import Analysis.Types.Unix
import Analysis.Types.Vulnerability
import Control.Lens
import Control.Monad
import qualified Data.HashMap.Strict as HM
import qualified Data.Map.Strict as M
import Data.Maybe (fromMaybe)
import Data.Oval
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import qualified Data.Text as T

listRPMs :: Analyzer (Seq ConfigInfo)
listRPMs = fmap SoftwarePackage . rpmInfos <$> requireTxt ["logiciels/rpm-qa.txt"]

rpmInfos :: T.Text -> Seq SoftwarePackage
rpmInfos = Seq.fromList . map getPackageinfo' . T.lines
  where
    getPackageinfo' t = fromMaybe (error ("Invalid package name: " ++ show t)) (getPackageinfo t)

runAnalyze ::
  UnixVersion ->
  T.Text -> -- architecture
  M.Map T.Text RPMVersion ->
  ([OvalDefinition], HM.HashMap OTestId OFullTest) ->
  Seq Vulnerability
runAnalyze unix arch packagemap (ovs, tests) = do
  ov@(OvalDefinition _ t _ d _ sev _ day) <- Seq.fromList ovs
  let (matched, pkgs) = ovalRuleMatchedRPM unix arch packagemap tests ov
  guard matched
  (pkg, correctver) <- Seq.fromList pkgs
  let mvulnver = packagemap ^. at pkg
  return $ Vulnerability sev $ OutdatedPackage $ case mvulnver of
    Nothing -> OP pkg "zozo" (descRPMVersion correctver) day (Just (t <> "\n" <> d))
    Just vulnver -> OP pkg (descRPMVersion vulnver) (descRPMVersion correctver) day (Just (t <> "\n" <> d))

mkrpmmap :: Seq ConfigInfo -> M.Map T.Text RPMVersion
mkrpmmap = M.fromList . toListOf (folded . _SoftwarePackage . to mrpm . folded)
  where
    mrpm (Package p v PRPM) = Just (p, parseRPMVersion (T.unpack v))
    mrpm _ = Nothing

postRPMAnalysis ::
  (UnixVersion -> Maybe (Once ([OvalDefinition], HM.HashMap OTestId OFullTest))) ->
  Seq ConfigInfo ->
  IO (Seq Vulnerability)
postRPMAnalysis = postOvalAnalysis mkrpmmap runAnalyze

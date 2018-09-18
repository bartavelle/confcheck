{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
module Analysis.RPM (listRPMs, postRPMAnalysis, runAnalyze) where


import Data.Oval
import Analysis.Types
import Analysis.Oval
import Analysis.Common

import Control.Lens
import qualified Data.Text as T
import qualified Data.Map.Strict as M
import qualified Data.HashMap.Strict as HM
import Control.Monad
import qualified Data.Sequence as Seq
import Data.Maybe (fromMaybe)
import Data.Sequence (Seq)
import Data.Monoid

listRPMs :: Analyzer (Seq ConfigInfo)
listRPMs = fmap SoftwarePackage . rpmInfos <$> requireTxt ["logiciels/rpm-qa.txt"]

rpmInfos :: T.Text -> Seq SoftwarePackage
rpmInfos = Seq.fromList . map getPackageinfo' . T.lines
    where
        getPackageinfo' = fromMaybe (error "Invalid package name") . getPackageinfo

runAnalyze :: UnixVersion 
           -> T.Text -- architecture
           -> M.Map T.Text RPMVersion
           -> ([OvalDefinition], HM.HashMap OTestId OFullTest)
           -> Seq Vulnerability
runAnalyze unix arch packagemap (ovs, tests) = do
    ov@(OvalDefinition _ t _ d _ sev _ day) <- Seq.fromList ovs
    let (matched, pkgs) = ovalRuleMatchedRPM unix arch packagemap tests ov
    guard matched
    (pkg, correctver) <- Seq.fromList pkgs
    let mvulnver = packagemap ^. at pkg
    case mvulnver of
        Nothing -> return $ Vulnerability sev $ OutdatedPackage pkg "zozo" (descRPMVersion correctver) day (Just (t <> "\n" <> d))
        Just vulnver -> return $ Vulnerability sev $ OutdatedPackage pkg (descRPMVersion vulnver) (descRPMVersion correctver) day (Just (t <> "\n" <> d))

mkrpmmap :: Seq ConfigInfo -> M.Map T.Text RPMVersion
mkrpmmap = M.fromList . toListOf (folded . _SoftwarePackage . to mrpm . folded)
    where
        mrpm (Package p v PRPM) = Just (p, parseRPMVersion (T.unpack v))
        mrpm _ = Nothing

postRPMAnalysis :: (UnixVersion -> Maybe (Once ([OvalDefinition], HM.HashMap OTestId OFullTest))) -> Seq ConfigInfo -> IO (Seq Vulnerability)
postRPMAnalysis ovaldispatch ce =
    case (,) <$> extractVersion ce <*> extractArch ce of
        Just (v, arch) ->
          case ovaldispatch v of
            Just ov -> runAnalyze v arch (mkrpmmap ce) <$> getOnce ov
            Nothing -> return mempty
        _ -> return mempty

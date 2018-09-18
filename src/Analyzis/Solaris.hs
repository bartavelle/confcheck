{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE RankNTypes #-}
module Analyzis.Solaris (
    anaShowRev
  , anaPkgInfo
  , loadPatchDiag
  , postSolarisAnalyzis
  , PatchInfo
  , patchIdent
  , patchDate
  , patchFlags
  , patchVersion
  , patchIncompatibles
  , patchRequires
  ) where

import Analyzis.Common
import Analyzis.Types

import Prelude
import Data.Text (Text)
import Data.List
import Data.Set (Set)
import Data.Set.Lens
import qualified Data.Set as S
import qualified Data.Map.Strict as M
import Data.Maybe (mapMaybe,fromMaybe)
import Control.Lens
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Control.Monad
import Text.Parsec.Text
import Text.Parsec.Char (digit, char, string)
import Text.Parsec.Prim (parse)
import Control.Applicative
import Data.Monoid
import Data.Time (fromGregorian, Day)
import qualified Data.Sequence as Seq
import Data.Sequence (Seq)
import qualified Data.Foldable as F
import qualified Data.Parsers.Helpers as H

data PatchFlag = Recommended
               | Security
               | Obsolete
               | Y2K
               | Bad
               deriving (Show, Ord, Eq)

data PatchVersion = Unbundled
                  | Solaris Int (Maybe PatchArch)
                  | TSolaris Text
                  | Dunno
                  deriving Show

data PatchArch = ArchX86
               deriving Show

data PatchInfo = PatchInfo { _patchIdent         :: !SolarisPatch
                           , _patchDate          :: !Day
                           , _patchFlags         :: !(Set PatchFlag)
                           , _patchVersion       :: !PatchVersion
                           , _patchRequires      :: !(Set SolarisPatch)
                           , _patchAffectedPkgs  :: !(Set SoftwarePackage)
                           , _patchIncompatibles :: !(Set SolarisPatch)
                           , _patchSynopsis      :: !Text
                           } deriving Show

makeLenses ''PatchInfo

_SolPackage :: Prism' Text SoftwarePackage
_SolPackage = prism' disply getPackageId
    where
        disply (Package n v _) = n <> ":" <> v
        getPackageId x | not (T.null ver) = Just $ Package pname (T.tail ver) PSolaris
                       | otherwise = Nothing
           where (pname, ver) = T.break (==':') x

parsePatchId :: Parser SolarisPatch
parsePatchId = do
    s <- replicateM 6 digit
    void (char '-')
    n <- replicateM 2 digit
    return ( SolarisPatch (read s) (read n) )

_SolarisPatch :: Prism' T.Text SolarisPatch
_SolarisPatch = prism' dsply (preview (parseFold parsePatchId))
    where
        dsply :: SolarisPatch -> T.Text
        dsply (SolarisPatch i r) = d 6 i <> "-" <> d 2 r
        d n = T.justifyRight n '0' . T.pack . show

parseFold :: Parser a -> Fold T.Text a
parseFold p = to (parse p "dummy") . _Right

parseShowRev :: T.Text -> [SolarisPatch]
parseShowRev = toListOf (traverse . parseFold (string "Patch: " *> parsePatchId)) . T.lines

-- | se récupère à partir d'un lien de
-- https://blogs.oracle.com/patch/entry/useful_patch_related_downloads
loadPatchDiag :: FilePath -> IO [PatchInfo]
loadPatchDiag = fmap (mapMaybe parseLine . T.lines) . T.readFile
    where
        getFlags pr ps po pby = ppr <> pps <> ppo <> py2k <> pbad
            where
                flag var val r | var == val = S.singleton r
                               | var == " " = mempty
                               | otherwise = error ("Flag parsing failed with:" <> show var <> " expected " <> show val)
                ppr = flag pr "R" Recommended
                pps = flag ps "S" Security
                ppo = flag po "O" Obsolete
                py2k = flag (T.take 1 pby) "Y" Y2K
                pbad = flag (T.drop 1 pby) "B" Bad
        getOs "Unbundled" = Unbundled
        getOs "10" = Solaris 10 Nothing
        getOs "9" = Solaris 9 Nothing
        getOs "8" = Solaris 8 Nothing
        getOs "7" = Solaris 7 Nothing
        getOs "2.6" = Solaris 6 Nothing
        getOs "10_x86" = Solaris 10 (Just ArchX86)
        getOs "9_x86" = Solaris 9 (Just ArchX86)
        getOs "8_x86" = Solaris 8 (Just ArchX86)
        getOs "7_x86" = Solaris 7 (Just ArchX86)
        getOs x = case T.stripPrefix "Trusted_Solaris_" x of
                      Just t -> TSolaris t
                      Nothing -> Dunno
        getIdentifier i r = SolarisPatch <$> (read <$> preview (parseFold (replicateM 6 digit)) i)
                                         <*> (read <$> preview (parseFold (many digit)) r)
        prsDate :: T.Text -> Day
        prsDate "" = fromGregorian 1970 1 1
        prsDate t = case T.splitOn "/" t of
                          [m, d, y] -> fromGregorian (toY (read (T.unpack y))) (parseMonth m) (read (T.unpack d))
                          _ -> error ("Can't parse date: " <> show t)
        toY y | y > 70 = y + 1900
              | otherwise = y + 2000
        parseMonth x = case H.englishMonth x of
                          Just m -> m
                          Nothing -> error ("Can't parse month: " <> show x)
        parseLine l
            | T.null l = Nothing
            | T.head l == '#' = Nothing
            | otherwise = case T.splitOn "|" l of
                              [pid, prev, pdate, pr, ps, po, pby, pos, parchs, ppkgs, psyn] ->
                                let reqs = setOf (traverse . _SolarisPatch) (T.splitOn ";" parchs)
                                    (incomp, apkgs) = partition (has _SolarisPatch) (T.splitOn ";" ppkgs)
                                                        & _1 %~ setOf (traverse . _SolarisPatch)
                                                        & _2 %~ setOf (traverse . _SolPackage)
                                in   Just $ PatchInfo (fromMaybe (error "patchinfo") (getIdentifier pid prev))
                                                      (prsDate pdate)
                                                      (getFlags pr ps po pby)
                                                      (getOs pos)
                                                      reqs
                                                      apkgs
                                                      incomp
                                                      psyn
                              _ -> error ("Analyzis.Solaris.parseLine: " <> show l)

data PackageIdKey = Pkg T.Text
                  | Ver T.Text
                  deriving Show

parsePkginfoL :: T.Text -> [SoftwarePackage]
parsePkginfoL = pairstuff . mapMaybe groupiert . T.lines
    where
        pairstuff [] = []
        pairstuff ( Pkg p : Ver v : xs ) = Package p v PSolaris : pairstuff xs
        pairstuff x = error ("Could not load pkg info: " <> show x)
        groupiert t = case map T.strip (T.splitOn ":  " t) of
                          ["PKGINST",v] -> Just (Pkg v)
                          ["VERSION",v] -> Just (Ver v)
                          _ -> Nothing

anaPkgInfo :: Analyzer (Seq ConfigInfo)
anaPkgInfo = Seq.fromList . map SoftwarePackage . parsePkginfoL <$> requireTxt ["logiciels/pkginfo-l.txt"]

anaShowRev :: Analyzer (Seq ConfigInfo)
anaShowRev = Seq.fromList . map SolPatch . parseShowRev <$> requireTxt ["logiciels/showrev-p.txt"]


missingPatches :: [PatchInfo] -> [SolarisPatch] -> [SoftwarePackage] -> Seq Vulnerability
missingPatches diag showrev pkgs = fmap (Vulnerability High) (notuptodate <> packagesNotPatched)
    where
        notuptodate :: Seq VulnType
        notuptodate = F.foldMap isUptodate (Seq.fromList showrev)
        installedPatches = setOf (traverse . solPatchId) showrev
        installedPackagesWVersion = setOf traverse pkgs
        installedPackages = setOf (folded . packageName) pkgs
        packagesNotPatched = do
            secpatch <- Seq.fromList securitypatches
            -- on vérifie qu'on a pas déjà un patch installé
            guard (hasn't (ix (secpatch ^. patchIdent . solPatchId)) installedPatches)
            -- on vérifie que ça correspond bien à un package installé
            let dependentPackages = setOf (patchAffectedPkgs . folded) secpatch
            guard (not (S.null dependentPackages))
            guard (dependentPackages `S.isSubsetOf` installedPackagesWVersion)
            return ( MissingPatch (secpatch ^. patchIdent . re _SolarisPatch )
                                  (secpatch ^. patchDate)
                                  (Just (secpatch ^. patchSynopsis))
                   )
        bestPatch :: M.Map Int PatchInfo
        bestPatch = M.fromListWith keepbest $ map (\p -> (p ^. patchIdent . solPatchId, p)) securitypatches
        getImpactedPackages :: PatchInfo -> S.Set Text
        getImpactedPackages p = setOf (patchAffectedPkgs . folded . packageName) p
                                        `S.intersection` installedPackages
        -- Garde la révisision la plus élevée
        keepbest :: PatchInfo -> PatchInfo -> PatchInfo
        keepbest p1 p2 | p1 ^. patchIdent . solPatchRev > p2 ^. patchIdent . solPatchRev = p1
                       | otherwise = p2
        isUptodate pa@(SolarisPatch p r) =
            case bestPatch ^? ix p of
                Just xd -> if xd ^. patchIdent . solPatchRev > r
                               then do
                                       impacted <- Seq.fromList (S.toList (getImpactedPackages xd))
                                       return (OutdatedPackage
                                                   impacted
                                                   (pa ^. re _SolarisPatch)
                                                   (xd ^. patchIdent . re _SolarisPatch)
                                                   (xd ^. patchDate)
                                                   (Just (xd ^. patchSynopsis))
                                              )
                               else mempty
                _ -> mempty
        securitypatches = filter (importantPatch . _patchFlags) diag
        importantPatch s | Bad `S.member` s = False
                         | Obsolete `S.member` s = False
                         | otherwise = Security `S.member` s

postSolarisAnalyzis :: Once [PatchInfo] -> Seq ConfigInfo -> IO (Seq Vulnerability)
postSolarisAnalyzis opi ci =
    let sp = ci ^.. folded . _SolPatch
        pk = ci ^.. folded . _SoftwarePackage
    in  if null pk
            then return mempty
            else do
                p <- getOnce opi
                return (missingPatches p sp pk)

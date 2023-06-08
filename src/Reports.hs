{-# LANGUAGE ImportQualifiedPost #-}
module Reports where

import Analysis (ficheData)
import Analysis.Fiche
import Analysis.Types
import Control.Lens (itoList)
import Data.List (intercalate)
import Data.Map.Strict qualified as M
import Data.Maybe (mapMaybe)
import Data.Sequence (Seq)
import Data.Set qualified as S
import Data.String (IsString (fromString))
import Data.Text (Text)
import Data.Text qualified as T
import Prettyprinter
import Prettyprinter.Render.Terminal
import Prettyprinter.Render.Text qualified as T
import Prettyprinter.Util (reflow)

data DisplayMode
  = Raw
  | Ansi
  deriving (Show, Eq, Ord, Enum, Read, Bounded)

data ReportSection
  = SectionHeader
  | SectionProblems
  | SectionUsers
  | SectionPackagelist
  | SectionFS
  | SectionDirectory
  | SectionPackageVulns
  | SectionNetwork
  | SectionApps
  | SectionMisc
  deriving (Show, Eq, Ord, Enum, Bounded)

defaultSections :: S.Set ReportSection
defaultSections =
  S.fromList
    [ SectionHeader,
      SectionProblems,
      SectionUsers,
      SectionFS,
      SectionPackageVulns,
      SectionMisc
    ]

showReport ::
  DisplayMode ->
  [ReportSection] ->
  Seq Vulnerability ->
  IO ()
showReport mode sections = showFiche mode sections . ficheData

showFiche ::
  DisplayMode ->
  [ReportSection] ->
  FicheInfo ->
  IO ()
showFiche mode sections = displayFunc . prettyFiche sections
  where
    displayFunc =
      case mode of
        Raw -> T.putDoc
        Ansi -> putDoc

prettyFiche ::
  [ReportSection] ->
  FicheInfo ->
  Doc AnsiStyle
prettyFiche sections finfo = vsep (mapMaybe showSection sections ++ [mempty])
  where
    showSection sec =
      case sec of
        SectionHeader -> Just (prettyHeader (_ficheHostname finfo) (_ficheOS finfo))
        SectionProblems -> Just (prettyProblems finfo)
        SectionUsers -> Just (prettyUsers (_ficheUsers finfo))
        SectionPackageVulns -> Just (prettyVulns (_fichePkgVulns finfo))
        SectionPackagelist -> undefined
        SectionFS -> Just (viaShow (_ficheFSProblems finfo))
        SectionDirectory -> fmap (\d -> "Directory: " <> text d) (_ficheAnnuaire finfo)
        SectionNetwork -> Just ("network: " <> viaShow (_ficheIfaces finfo))
        SectionApps -> Just ("apps: " <> viaShow (_ficheApplications finfo))
        SectionMisc -> Just (viaShow (_ficheProblems finfo))

prettyVulns :: JMap RPMVersion PackageUniqInfo -> Doc AnsiStyle
prettyVulns = vsep . map showP . itoList
  where
    showP (curv, PackageUniqInfo sev _ _ desc patches) = vcat [title, indent 4 body] <> hardline
      where
        title = psev sev <+> list (map pretty desc) <+> "-" <+> fromString (getRPMString curv)
        psev :: Severity -> Doc AnsiStyle
        psev s = case s of
          Unknown -> "UNK"
          None -> annotate (color Green) "NON"
          Low -> annotate (color Yellow) "LOW"
          Medium -> annotate (color Magenta) "MED"
          High -> annotate (color Red <> bold) "HIG"
          CVSS x -> psev (fromCVSS x)
        body = vcat (map mkPatch patches)
        mkPatch (pd, pv, ps, pt) =
          group $
            psev ps <+> fromString (getRPMString pv) <+> viaShow pd <+> pretty (T.unwords $ T.lines pt)

prettyHeader :: Maybe Text -> UnixVersion -> Doc AnsiStyle
prettyHeader mhostname version = foldMap (pretty . T.strip) mhostname <+> prettyUnixVersion version

prettyUnixVersion :: UnixVersion -> Doc AnsiStyle
prettyUnixVersion (UnixVersion ut v) = put <+> pv
  where
    put = case ut of
      Debian -> "Debian"
      RHEL -> "RedHat Enterprise Linux"
      RedHatLinux -> "RedHat"
      CentOS -> "CentOS"
      SunOS -> "SunOS"
      SuSE -> "SuSE"
      OpenSuSE -> "OpenSuSE"
      Ubuntu -> "Ubuntu"
      Unk x -> pretty x
      Fedora -> "Fedora"
      OpenSUSELeap -> "openSUSE Leap"
    pv = fromString (intercalate "." (map show v))

text :: Text -> Doc AnsiStyle
text = fromString . T.unpack

prettyProblems :: FicheInfo -> Doc AnsiStyle
prettyProblems finfo = vsep ("# PROBLEMS" : mpatches)
  where
    missing_patches = _fichePackages finfo
    mpatches
      | null missing_patches = mempty
      | otherwise = map showMissingPatch missing_patches
    showMissingPatch (day, sev, desc, installed, patch) =
      indent
        2
        ( "[" <> fromString (show sev) <> "/" <> fromString (show day) <> "]"
            <+> text desc
            <+> text installed
            <+> "->"
            <+> text patch
        )

prettyUsers ::
  ( [UnixUser],
    [UnixUser],
    M.Map Text [AppUser]
  ) ->
  Doc AnsiStyle
prettyUsers = reflow . fromString . show

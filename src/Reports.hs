module Reports where

import           Data.List
import qualified Data.Map.Strict                           as M
import           Data.Maybe                                (mapMaybe)
import           Data.Sequence                             (Seq)
import qualified Data.Set                                  as S
import           Data.String
import           Data.Text                                 (Text)
import qualified Data.Text                                 as T
import           Data.Text.Prettyprint.Doc
import           Data.Text.Prettyprint.Doc.Render.Terminal
import qualified Data.Text.Prettyprint.Doc.Render.Text     as T
import           Data.Text.Prettyprint.Doc.Util            (reflow)

import           Analysis                                  (ficheData)
import           Analysis.Fiche
import           Analysis.Types.Unix
import           Analysis.Types.UnixUsers
import           Analysis.Types.Vulnerability
import           Analysis.Types.Windows

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
defaultSections = S.fromList
    [ SectionHeader
    , SectionProblems
    , SectionUsers
    , SectionFS
    , SectionPackageVulns
    , SectionMisc
    ]

showReport
  :: DisplayMode
  -> [ReportSection]
  -> Seq Vulnerability
  -> IO ()
showReport mode sections = displayFunc . prettyFiche sections . ficheData
  where
    displayFunc =
      case mode of
        Raw -> T.putDoc
        Ansi -> putDoc

prettyFiche
  :: [ReportSection]
  -> FicheInfo
  -> Doc AnsiStyle
prettyFiche sections finfo = vsep (mapMaybe showSection sections ++ [mempty])
  where
    showSection sec =
      case sec of
        SectionHeader -> Just (prettyHeader (_ficheHostname finfo) (_ficheOS finfo))
        SectionProblems -> Just (prettyProblems finfo)
        SectionUsers -> Just (prettyUsers (_ficheUsers finfo))
        _ -> Just ("TODO: " <+> fromString (show sec))

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
            WindowsClient x -> "Windows Client " <> pretty x
            WindowsServer x -> "Windows Server " <> pretty x
            Fedora -> "Fedora"
            OpenSUSELeap -> "openSUSE Leap"

    pv = fromString (intercalate "." (map show v))

text :: Text -> Doc AnsiStyle
text = fromString . T.unpack

prettyProblems :: FicheInfo -> Doc AnsiStyle
prettyProblems finfo = vsep ("# PROBLEMS" : mpatches)
  where
    missing_patches = _fichePackages finfo
    mpatches | null missing_patches = mempty
             | otherwise = map showMissingPatch missing_patches
    showMissingPatch (day, sev, desc, installed, patch) = indent 2 (
        "[" <> fromString (show sev) <> "/" <> fromString (show day) <> "]"
        <+> text desc
        <+> text installed <+> "->" <+> text patch)

prettyUsers
  :: ( [UnixUser]
     , [UnixUser]
     , [WinUser]
     , [WinUser]
     , M.Map Text [AppUser])
  -> Doc AnsiStyle
prettyUsers = reflow . fromString . show

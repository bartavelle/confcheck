{-# LANGUAGE LambdaCase #-}
module Main where

import           Analysis                     ( analyzeFile )
import           Analysis.Common              ( mkOnce )
import           Analysis.Oval                ( ovalOnce )
import           Analysis.Solaris             ( loadPatchDiag )
import           Analysis.Types.Helpers       ( AuditFileType (..) )
import           Analysis.Types.Vulnerability
import           Data.Microsoft               ( loadKBDays )
import           Reports                      ( DisplayMode (..), ReportSection (..), defaultSections, showReport )

import           Control.Lens
import           Control.Monad
import qualified Data.ByteString.Lazy.Char8   as BSL
import           Data.Csv                     ( encode )
import qualified Data.Foldable                as F
import           Data.List
import qualified Data.Set                     as S
import qualified Data.Text                    as T
import           Options.Applicative

import           Prelude

data Options = Options [ReportSection] DisplayMode RunMode [FilePath]
    deriving Show

data RunMode
    = Standard
    | CSV
    | Patches
    | ShowD
    deriving (Show, Eq, Ord, Enum, Bounded)

data Switch x
    = Enable x
    | Disable x
    deriving (Show, Eq)

sections :: Parser [ReportSection]
sections = S.toList . foldl' applySwitch defaultSections <$> many sectionflag
  where
    sectionflag = F.asum (map mkSecOption [minBound .. maxBound])
    mkSecOption sec 
      = let secname = drop 7 (show sec)
            (optname, switcher, desc) =
              if S.member sec defaultSections
                then ("without", Disable, "Disable")
                else ("with", Enable, "Enable")
        in  flag' (switcher sec) (long (optname <> secname) <> help (desc <> " reporting of section " <> secname))
    applySwitch cursections sw =
      case sw of
        Enable x -> S.insert x cursections
        Disable x -> S.delete x cursections

options :: Parser Options
options = Options <$> sections <*> displaymode <*> runmode <*> some file
  where
    displaymode = pure Ansi
    parseMode = maybeReader $ \case
        "csv" -> Just CSV
        "patches" -> Just Patches
        "standard" -> Just Standard
        "raw" -> Just ShowD
        _ -> Nothing
    runmode = option parseMode
      (  long "mode"
      <> short 'm'
      <> value Standard
      <> help "Mode, valid values are standard, csv and patches"
      )
    file = strArgument (help "Files to analyze" <> metavar "FILE")

main :: IO ()
main = do
    let commandParser = info (options <**> helper)
                             ( fullDesc
                             <> progDesc "Analyzes configuration dumps"
                             <> header "confcheck-exe - analyze configuration dumps"
                             )
    Options secs dmode runmode files <- execParser commandParser
    xdiag      <- mkOnce (loadPatchDiag "sources/patchdiag.xref")
    ov   <- ovalOnce "serialized"
    okbd <- mkOnce (loadKBDays "serialized/BulletinSearch.serialized")
    case runmode of
      CSV -> do
        res <- mconcat <$> mapM (analyzeFile AuditTarGz xdiag ov okbd) files
        BSL.putStrLn (encode (map toRecord (F.toList res)))
      Patches -> do
        res <- mconcat <$> mapM (analyzeFile AuditTarGz xdiag ov okbd) files
        let missings = res ^.. traverse . _Vulnerability . aside _OutdatedPackage
            toPatchRecord (sev, OP titre installed patched pub _) 
              = [show pub, show sev, T.unpack titre, T.unpack installed, T.unpack patched]

        BSL.putStrLn (encode (map toPatchRecord (F.toList missings)))
      Standard -> mapM_ (analyzeFile AuditTarGz xdiag ov okbd >=> showReport dmode secs) files
      ShowD -> forM_ files $ \p -> do
        putStrLn ("Parsing " ++ p)
        analyzeFile AuditTarGz xdiag ov okbd p >>= mapM_ print

toRecord :: Vulnerability -> [String]
toRecord v 
  = case v of
      Vulnerability sev (OutdatedPackage (OP titre installed patched pub mtest)) 
        -> ["Patch", show sev, T.unpack titre, T.unpack installed, T.unpack patched, show pub, maybe mempty T.unpack mtest]
      Vulnerability sev det -> ["Vulnerabilité", show sev, show det]
      ConfigInformation det -> ["Information", "", show det]
      SomethingToCheck -> ["??"]

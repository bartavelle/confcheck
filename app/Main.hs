{-# LANGUAGE LambdaCase #-}
module Main where

import           Analysis
import           Analysis.Common
import           Analysis.Oval
import           Analysis.Solaris
import           Analysis.Types.Helpers       (AuditFileType (..))
import           Analysis.Types.Vulnerability
import           Data.Microsoft

import           Control.Lens
import           Control.Monad
import qualified Data.ByteString.Lazy.Char8   as BSL
import           Data.Csv                     (encode)
import qualified Data.Foldable                as F
import qualified Data.Text                    as T
import           Options.Applicative

import           Prelude

data Options = Options RunMode [FilePath]
    deriving Show

data RunMode
    = Standard
    | CSV
    | Patches
    deriving (Show, Eq, Ord, Enum, Bounded)

options :: Parser Options
options = Options <$> runmode <*> some file
  where
    parseMode = maybeReader $ \case
        "csv"      -> Just CSV
        "patches"  -> Just Patches
        "standard" -> Just Standard
        _          -> Nothing
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
    Options runmode files <- execParser commandParser
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
            toPatchRecord (sev, (titre, installed, patched, pub, _))
              = [show pub, show sev, T.unpack titre, T.unpack installed, T.unpack patched]

        BSL.putStrLn (encode (map toPatchRecord (F.toList missings)))
      Standard -> mapM_ (analyzeFile AuditTarGz xdiag ov okbd >=> mapM_ print) files

toRecord :: Vulnerability -> [String]
toRecord v
  = case v of
      Vulnerability sev (OutdatedPackage titre installed patched pub mtest)
        -> ["Patch", show sev, T.unpack titre, T.unpack installed, T.unpack patched, show pub, maybe mempty T.unpack mtest]
      Vulnerability sev det -> ["Vulnerabilité", show sev, show det]
      ConfigInformation det -> ["Information", "", show det]
      SomethingToCheck      -> ["??"]

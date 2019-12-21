module Main where

import           Analysis
import           Analysis.Common
import           Analysis.Oval
import           Analysis.Solaris
import           Analysis.Types
import           Data.Microsoft

import           Debug.Trace

import           Control.Lens
import           Control.Monad
import qualified Data.ByteString.Lazy.Char8 as BSL
import           Data.Csv                   (encode)
import qualified Data.Foldable              as F
import qualified Data.Text                  as T
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
    parseMode = maybeReader $ \s ->
      case s of
        "csv"      -> Just CSV
        "patches"  -> Just Patches
        "standard" -> Just Standard
        _          -> Nothing
    runmode = option parseMode (long "mode" <> short 'm' <> value Standard <> help "Mode, valid values are standard, csv and patches")
    file = strArgument (help "Files to analyze" <> metavar "FILE")

main :: IO ()
main = do
    let commandParser = info (options <**> helper)
                             (fullDesc <> progDesc "Analyzes configuration dumps" <> header "confcheck-exe - analyze configuration dumps")
    Options runmode files <- execParser commandParser
    xdiag      <- mkOnce (loadPatchDiag "sources/patchdiag.xref")
    rhoval     <- mkOnce (loadOvalSerialized "serialized/com.redhat.rhsa-all.xml")
    s11oval    <- mkOnce (loadOvalSerialized "serialized/suse.linux.enterprise.server.11.xml")
    os122oval  <- mkOnce (loadOvalSerialized "serialized/opensuse.12.2.xml")
    os123oval  <- mkOnce (loadOvalSerialized "serialized/opensuse.12.3.xml")
    os132oval  <- mkOnce (loadOvalSerialized "serialized/opensuse.13.2.xml")
    ubuntu1404 <- mkOnce (loadOvalSerialized "serialized/com.ubuntu.trusty.cve.oval.xml")
    ubuntu1604 <- mkOnce (loadOvalSerialized "serialized/com.ubuntu.xenial.cve.oval.xml")
    ubuntu1804 <- mkOnce (loadOvalSerialized "serialized/com.ubuntu.bionic.cve.oval.xml")
    deb7       <- mkOnce (loadOvalSerialized "serialized/oval-definitions-wheezy.xml")
    deb8       <- mkOnce (loadOvalSerialized "serialized/oval-definitions-jessie.xml")
    deb9       <- mkOnce (loadOvalSerialized "serialized/oval-definitions-stretch.xml")
    deb10      <- mkOnce (loadOvalSerialized "serialized/oval-definitions-buster.xml")
    okbd <- mkOnce (loadKBDays "serialized/BulletinSearch.serialized")
    let ov v = case v of
                   UnixVersion SuSE (11:_)     -> Just s11oval
                   UnixVersion RedHatLinux _   -> Just rhoval
                   UnixVersion RHEL _          -> Just rhoval
                   UnixVersion CentOS _        -> Just rhoval
                   UnixVersion OpenSuSE [12,2] -> Just os122oval
                   UnixVersion OpenSuSE [12,3] -> Just os123oval
                   UnixVersion OpenSuSE [13,2] -> Just os132oval
                   UnixVersion Ubuntu [14,4]   -> Just ubuntu1404
                   UnixVersion Ubuntu [16,4]   -> Just ubuntu1604
                   UnixVersion Ubuntu [18,4]   -> Just ubuntu1804
                   UnixVersion Debian [7,_]    -> Just deb7
                   UnixVersion Debian [8,_]    -> Just deb8
                   UnixVersion Debian [9,_]    -> Just deb9
                   UnixVersion Debian [10,_]   -> Just deb10
                   _ -> trace ("Unknown os " ++ show v) Nothing
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


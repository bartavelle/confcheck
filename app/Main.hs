module Main where

import Analyzis
import Analyzis.Types
import Analyzis.Oval
import Analyzis.Solaris
import Analyzis.Debian
import Analyzis.Common
import Data.Microsoft

import Debug.Trace

import System.Environment
import Control.Monad
import Data.Csv (encode)
import qualified Data.ByteString.Lazy.Char8 as BSL
import qualified Data.Foldable as F
import qualified Data.Text as T
import Prelude

main :: IO ()
main = do
    xdiag      <- mkOnce (loadPatchDiag "source/patchdiag.xref")
    rhoval     <- mkOnce (loadOvalSerialized "serialized/com.redhat.rhsa-all.xml")
    s11oval    <- mkOnce (loadOvalSerialized "serialized/suse.linux.enterprise.server.11.xml")
    os122oval  <- mkOnce (loadOvalSerialized "serialized/opensuse.12.2.xml")
    os123oval  <- mkOnce (loadOvalSerialized "serialized/opensuse.12.3.xml")
    os132oval  <- mkOnce (loadOvalSerialized "serialized/opensuse.13.2.xml")
    ubuntu1404 <- mkOnce (loadOvalSerialized "serialized/com.ubuntu.trusty.cve.oval.xml")
    ubuntu1604 <- mkOnce (loadOvalSerialized "serialized/com.ubuntu.xenial.cve.oval.xml")
    let cveserial = "serialized/cve.cereal"
    debian <- mkOnce (loadDebVulns cveserial "source/debian-dsa")
    okbd <- mkOnce (loadKBDays ("serialized/BulletinSearch.serialized"))
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
                   _ -> trace ("Unknown os " ++ show v) Nothing
    args <- getArgs
    case args of
      "csv":rargs -> do
        res <- mconcat <$> mapM (analyzeFile AuditTarGz xdiag ov debian okbd) rargs
        BSL.putStrLn (encode (map toRecord (F.toList res)))
      _ -> mapM_ (analyzeFile AuditTarGz xdiag ov debian okbd >=> mapM_ print) args

toRecord :: Vulnerability -> [String]
toRecord v
  = case v of
      Vulnerability sev (OutdatedPackage titre installed patched pub mtest)
        -> ["Patch", show sev, T.unpack titre, T.unpack installed, T.unpack patched, show pub, maybe mempty T.unpack mtest]
      Vulnerability sev det -> ["Vulnerabilité", show sev, show det]
      ConfigInformation det -> ["Information", "", show det]
      SomethingToCheck      -> ["??"]


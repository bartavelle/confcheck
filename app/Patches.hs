{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Analysis                   ( PackageUniqInfo, ficheData )
import           Analysis.Common            ( Once, getOnce )
import qualified Analysis.Debian            as DEB
import           Analysis.Fiche             ( FicheInfo (_fichePkgVulns), JMap, pckPatches, pckSeverity )
import           Analysis.Oval              ( OvalContent, ovalOnce )
import qualified Analysis.RPM               as RPM
import           Analysis.Types
import           Control.Lens
import           Control.Monad              ( unless, when )
import           Data.Aeson                 ( encode )
import qualified Data.ByteString.Lazy.Char8 as BSL8
import           Data.Char                  ( toLower )
import           Data.Foldable              ( Foldable (toList) )
import qualified Data.Map.Strict            as M
import           Data.Sequence              ( Seq )
import qualified Data.Sequence              as Seq
import qualified Data.Text                  as T
import qualified Data.Text.IO               as T
import qualified Data.Text.Read             as T
import           Options.Applicative
import           Reports
import           System.IO                  ( hIsTerminalDevice, stderr, stdout )


data Options
  = Options
  { ovalPath :: FilePath
  , distribution :: UnixVersion
  , packagePath :: PackageFile
  , arch :: T.Text
  , displayJSON :: Bool
  , minVuln :: Severity
  } deriving (Show)


data PackageFile
  = PackageFile PackageType FilePath
  deriving Show


data PackageType
  = TRPM  -- ^ rpm -qa
  | TDEBS -- ^ dpkg-status
  | TDEB  -- ^ dpkg -l
  deriving (Show, Eq, Bounded, Enum)


options :: Parser Options
options 
  = Options
      <$> strOption ( long "path" <> metavar "PATH" <> help "Path to the oval serialized files" <> value "/usr/share/confcheck-cli/serialized" <> showDefault)
      <*> unixVersion
      <*> packagefile
      <*> strOption (long "arch" <> metavar "ARCH" <> help "Target architecture" <> value "x86_64" <> showDefault)
      <*> switch (long "json" <> help "JSON output")
      <*> minvuln


minvuln :: Parser Severity
minvuln = option (maybeReader sevreader) (long "severity" <> metavar "SEV" <> help "Minimum severity to display ('low', 'med', 'high')")
  where
    sevreader s 
      = case take 3 (map toLower s) of
          "low" -> pure Low
          "med" -> pure Medium
          "hig" -> pure High
          _ -> Nothing


packagefile :: Parser PackageFile
packagefile = (PackageFile TRPM <$> strOption ( long "rpm" <> metavar "PATH" <> help "Path to the output of rpm -qa" ))
          <|> (PackageFile TDEBS <$> strOption ( long "dpkgstatus" <> metavar "PATH" <> help "Path to the copy of /var/lib/dpkg/status" ))
          <|> (PackageFile TDEB <$> strOption ( long "dpkg" <> metavar "PATH" <> help "Path to the output of dpkg -l *WARNING* this will produce an incomplete output!!!" ))


unixVersion :: Parser UnixVersion
unixVersion = sles <|> rh <|> opensuse <|> opensuseleap <|> ubuntu <|> debian
  where
    mk c nm prettyname = option (eitherReader (fmap (UnixVersion c) . readVersion)) (long nm <> metavar "VERSION" <> help prettyname)
    sles = mk SuSE "sles" "SuSE Linux Enterprise Server"
    rh = mk RedHatLinux "rh" "RedHat Linux"
    opensuse = mk OpenSuSE "opensuse" "OpenSuSE"
    opensuseleap = mk OpenSUSELeap "leap" "OpenSUSE Leap"
    ubuntu = mk Ubuntu "ubuntu" "Ubuntu Linux"
    debian = mk Debian "debian" "Debian Linux"


readVersion :: String -> Either String [Int]
readVersion = mapM parseInt . T.splitOn "." . T.pack
  where
    parseInt t = do
      (num, rm) <- T.decimal t
      unless (T.null rm) (Left ("Extra characters after " ++ show rm))
      pure num


pinfo :: ParserInfo Options
pinfo = info (options <**> helper) (fullDesc <> progDesc "Get missing patches from packages lists")


analyze
  :: (Foldable f, Monoid (f SoftwarePackage))
  => (Seq ConfigInfo -> M.Map T.Text version)
  -> (T.Text -> f SoftwarePackage)
  -> ( UnixVersion
    -> T.Text -- architecture
    -> M.Map T.Text version
    -> OvalContent
    -> Seq Vulnerability
     )
  -> T.Text -- ^ content
  -> UnixVersion
  -> T.Text -- ^ arch
  -> Once OvalContent
  -> IO (Seq Vulnerability)
analyze mkmap parseLine analz content version a ocontent = analz version a mp <$> getOnce ocontent
  where
    packages = parseLine content
    mp = mkmap (fmap SoftwarePackage (Seq.fromList (toList packages)))


main :: IO ()
main = do
  opts <- execParser pinfo
  oonce <- ovalOnce (ovalPath opts)
  let PackageFile ptype pfilepath = packagePath opts
  cnt <- T.readFile pfilepath
  when (ptype == TDEB) (T.hPutStrLn stderr "Warning, using dpkg -l output will produce an incomplete output, using dpkg-status is recommended.")
  let analyze' = case ptype of
        TRPM -> analyze RPM.mkrpmmap RPM.rpmInfos RPM.runAnalyze
        TDEBS -> analyze DEB.mkdebmap DEB.parseDpkgStatus DEB.runOvalAnalyze
        TDEB -> analyze DEB.mkdebmap DEB.parseDpkgL DEB.runOvalAnalyze
  isTerm <- hIsTerminalDevice stdout
  let displayMode 
        = if isTerm
            then Ansi
            else Raw
  case oonce (distribution opts) of
    Just oo -> do
      vulns <- analyze' cnt (distribution opts) (arch opts) oo
      let finfo = ficheData vulns
          filtered_vulns :: JMap RPMVersion PackageUniqInfo
          filtered_vulns = _fichePkgVulns finfo & _Wrapped %~ M.mapMaybe (filterMap (minVuln opts))
          filtered_finfo = finfo { _fichePkgVulns = filtered_vulns }
      if displayJSON opts
        then BSL8.putStrLn (encode filtered_vulns)
        else showFiche displayMode [SectionPackageVulns] filtered_finfo
    Nothing -> putStrLn "Unsupported distribution"

filterMap :: Severity -> PackageUniqInfo -> Maybe PackageUniqInfo
filterMap sev puinfo
  | puinfo ^. pckSeverity >= sev = Just (puinfo & pckPatches %~ filter ((>= sev) . view _3))
  | otherwise = Nothing


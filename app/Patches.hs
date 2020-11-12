{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Analysis                   ( ficheData )
import           Analysis.Common            ( Once, getOnce )
import qualified Analysis.Debian            as DEB
import           Analysis.Fiche             ( FicheInfo (_fichePkgVulns) )
import           Analysis.Oval              ( OvalContent, ovalOnce )
import qualified Analysis.RPM               as RPM
import           Analysis.Types
import           Control.Monad              ( unless )
import           Data.Aeson                 ( encode )
import qualified Data.ByteString.Lazy.Char8 as BSL8
import           Data.Foldable              ( Foldable (toList) )
import qualified Data.Map.Strict            as M
import           Data.Sequence              ( Seq )
import qualified Data.Sequence              as Seq
import qualified Data.Text                  as T
import qualified Data.Text.IO               as T
import qualified Data.Text.Read             as T
import           Options.Applicative
import           Reports


data Options
  = Options
  { ovalPath :: FilePath
  , distribution :: UnixVersion
  , packagePath :: PackageFile
  , arch :: T.Text
  , displayJSON :: Bool
  } deriving (Show)

data PackageFile
  = PackageFile PackageType FilePath
  deriving Show

data PackageType
  = TRPM
  | TDEBS
  deriving Show

options :: Parser Options
options 
  = Options
      <$> strOption ( long "path" <> metavar "PATH" <> help "Path to the oval serialized files" <> value "/usr/share/confcheck-cli/serialized" <> showDefault)
      <*> unixVersion
      <*> packagefile
      <*> strOption (long "arch" <> metavar "ARCH" <> help "Target architecture" <> value "x86_64" <> showDefault)
      <*> switch (long "json" <> help "JSON output")

packagefile :: Parser PackageFile
packagefile = (PackageFile TRPM <$> strOption ( long "rpm" <> metavar "PATH" <> help "Path to the output of rpm -qa" ))
          <|> (PackageFile TDEBS <$> strOption ( long "dpkgstatus" <> metavar "PATH" <> help "Path to the copy of /var/lib/dpkg/status" ))

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
  let analyze' = case ptype of
        TRPM -> analyze RPM.mkrpmmap RPM.rpmInfos RPM.runAnalyze
        TDEBS -> analyze DEB.mkdebmap DEB.parseDpkgStatus DEB.runOvalAnalyze
  case oonce (distribution opts) of
    Just oo -> do
      vulns <- analyze' cnt (distribution opts) (arch opts) oo
      let finfo = ficheData vulns
      if displayJSON opts
        then BSL8.putStrLn (encode (_fichePkgVulns finfo))
        else showFiche Ansi [SectionPackageVulns] finfo
    Nothing -> putStrLn "Unsupported distribution"


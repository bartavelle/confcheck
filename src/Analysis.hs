{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE TupleSections     #-}
module Analysis ( RegroupedVulnerability(..)
                , PackageUniqInfo(..)
                , FicheInfo(..)
                , Deadline(..)
                , AppUser(..)
                , packageInfoToList
                , configExtract
                , regroupvulns
                , postAnalysis
                , analyzeFile
                , analyzeStream
                , ficheData
                , genvt
                , getAymlFile
                , regroupPackages
                ) where

import           Analysis.Common
import           Analysis.ConnectToApp        (buildNetApps)
import           Analysis.Cron
import           Analysis.Debian              (listDebs, postDebAnalysis)
import           Analysis.Fiche
import           Analysis.Files
import           Analysis.Ifconfig
import           Analysis.Ipaddr
import           Analysis.LinuxKern
import           Analysis.Netstat
import           Analysis.Passwd
import           Analysis.Rhosts
import           Analysis.RPM
import           Analysis.Solaris
import           Analysis.Sssd
import           Analysis.Sudoers
import           Analysis.Sysctl
import           Analysis.TarStream
import           Analysis.Types.ConfigInfo
import           Analysis.Types.Helpers
import           Analysis.Types.Network
import           Analysis.Types.Package
import           Analysis.Types.Unix
import           Analysis.Types.UnixUsers
import           Analysis.Types.Vulnerability
import           Analysis.Types.Windows
import           Analysis.Windows.SID
import           Analysis.WindowsAudit
import           Data.Microsoft
import           Data.Oval
import           Data.PrismFilter

import           Control.Applicative
import           Control.Arrow                ((&&&))
import           Control.Dependency           (guardResult)
import           Control.Lens
import           Control.Monad
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Resource (runResourceT)
import qualified Data.ByteString.Lazy         as BSL
import           Data.Conduit
import qualified Data.Conduit.List            as CL
import qualified Data.Conduit.Require         as R
import qualified Data.Conduit.Zlib            as CZ
import qualified Data.Foldable                as F
import qualified Data.HashMap.Strict          as HM
import qualified Data.IntMap.Strict           as IM
import           Data.List
import qualified Data.Map.Strict              as M
import           Data.Maybe                   (mapMaybe)
import           Data.Ord                     (comparing)
import           Data.Sequence                (Seq)
import qualified Data.Sequence                as Seq
import           Data.Sequence.Lens
import           Data.String                  (fromString)
import           Data.Text                    (Text)
import qualified Data.Text                    as T
import           Data.Textual                 (toText)
import           Data.Time                    (Day (..))

data RegroupedVulnerability = RV (Seq Vulnerability)
                            | RPack (M.Map RPMVersion PackageUniqInfo)
                            | RAuth (Seq UnixUser) (Seq Vulnerability)
                            | RNet [NetIf] [Connection]
                            | RFS [(Severity, FileVuln)]

makePrisms ''RegroupedVulnerability

regroupNet :: Seq Vulnerability -> RegroupedVulnerability
regroupNet vlns = RNet ifs cnx
    where
        ifs = toListOf (folded . _ConfigInformation . _CIf)         vlns
        cnx = toListOf (folded . _ConfigInformation . _CConnection) vlns

packageInfoToList :: M.Map RPMVersion PackageUniqInfo -> [(RPMVersion, PackageUniqInfo)]
packageInfoToList = sortBy zz . itoList
    where
    zz ( sv1 , PackageUniqInfo s1 d1 pv1 _ _ ) ( sv2 , PackageUniqInfo s2 d2 pv2 _ _ ) = compare s2 s1 <> compare d1 d2 <> compare sv1 sv2 <> compare pv1 pv2

regroupPackages :: Seq Vulnerability -> M.Map RPMVersion PackageUniqInfo
regroupPackages = M.fromListWith (<>) . mapMaybe mkp . F.toList
    where
        prpm = parseRPMVersion . T.unpack
        mkp (Vulnerability s (OutdatedPackage (OP p sv pv d md))) = Just ( prpm sv , PackageUniqInfo s d (prpm pv) [p] (md ^.. folded . to (d,prpm pv,s,)) )
        mkp (Vulnerability s (MissingPatch (MP ttl d desc))) = Just (fromString (T.unpack ttl), PackageUniqInfo s d "" (desc ^.. folded) [(d, "", s, desc ^. folded)])
        mkp x = error ("regroupPackages, new type of package entry: " ++ show x)

regroupVulnByType :: Seq Vulnerability -> M.Map VulnGroup (Seq Vulnerability)
regroupVulnByType = M.fromListWith (<>) . map (genvt &&& Seq.singleton) . F.toList

_VFileSev :: Prism' Vulnerability (Severity, FileVuln)
_VFileSev = prism' (\(sev, fv) -> Vulnerability sev (VFile fv)) $
    \v -> case v of
              Vulnerability sev (VFile fv) -> Just (sev, fv)
              _                            -> Nothing

regroupFS :: Seq Vulnerability -> RegroupedVulnerability
regroupFS = RFS . toListOf (folded . _VFileSev)

regroupvulns :: Seq Vulnerability -> M.Map VulnGroup RegroupedVulnerability
regroupvulns = imap regroupV . regroupVulnByType
    where
        regroupV :: VulnGroup -> Seq Vulnerability -> RegroupedVulnerability
        regroupV GPackages = RPack . regroupPackages
        regroupV GFS = regroupFS
        regroupV GNet = regroupNet
        regroupV GAuthUnix = \l -> RAuth (seqOf (folded . gu) l) (Seq.filter (hasn't gu) l)
            where
                gu :: Prism' Vulnerability UnixUser
                gu = _ConfigInformation . _ConfUnixUser
        regroupV _ = RV

genvt :: Vulnerability -> VulnGroup
genvt (Vulnerability _ vt) = case vt of
                                 OutdatedPackage{} -> GPackages
                                 MissingPatch{}    -> GPackages
                                 MultipleUser{}    -> GAuthUnix
                                 MultipleGroup{}   -> GAuthUnix
                                 MultipleShadow{}  -> GAuthUnix
                                 VRhost{}          -> GAuthUnix
                                 VFile{}           -> GFS
                                 MiscVuln{}        -> GMisc
                                 WrongSysctl{}     -> GMisc
genvt (ConfigInformation x) = case x of
                                  ConfPass _       -> GAuthUnix
                                  ConfShadow _     -> GAuthUnix
                                  ConfGroup _      -> GAuthUnix
                                  ConfUnixUser _   -> GAuthUnix
                                  ConfWinUser _    -> GAuthWin
                                  ConfWinGroup _   -> GAuthWin
                                  ConfWinLoginfo _ -> GAuthWin
                                  CSudo _          -> GAuthUnix
                                  CRhost _         -> GAuthUnix
                                  ConfigError _    -> GErrors
                                  ConfUnixFile _   -> GFS
                                  ConfUnixFileNG _ -> GFS
                                  BrokenLink _     -> GFS
                                  CCronEntry _     -> GCron
                                  CIf _            -> GNet
                                  CConnection _    -> GNet
                                  Sysctl _ _       -> GMisc
                                  _                -> GInfo
genvt x = error ("genvt not implemented for " <> show x)

configExtract :: [(R.RunMode, Analyzer (Seq ConfigInfo))]
configExtract = map (R.OnceCorrect,) corrects <> map (R.Once,) once <> map (R.Reset,) reset
    where
        mk a = fmap (return . a)
        corrects =
          [ mk UVersion unixVersion
          ]
        reset = [ anaUsercrontab
                , anaCrontab
                , anasudo
                , anaRhosts
                ]
        once = anaPkgInfo
             : anaShowRev
             : anaNetstat
             : anaFilesNG
             : anaFilesOld
             : (nn anaIpaddr <|> nn anaIfconfig)
             : anaSysctl
             : anaKernel
             : listRPMs
             : listDebs
             : anaSssd
             : getHostname
             : analyzePasswdfile
        nn = guardResult (not . null)

getHostname :: Analyzer (Seq ConfigInfo)
getHostname = Seq.singleton . Hostname <$> (requireTxtS "etc/hostname" <|> requireTxtS "etc/HOSTNAME" <|> fmap extraHNline (requireTxtS "etc/sysconfig/network") )
    where
        requireTxtS t = requireTxt ["conf/etc.tar.gz", t] <|> requireTxt ["conf/etc.tar.gz", T.cons '/' t]
        extraHNline t = case filter (\x -> length x > 1 && head x == "HOSTNAME") ( map (T.splitOn "=") ( T.lines t ) ) of
                            ( (_:x:_) : _) -> x
                            _              -> mempty
                            -- head . map (head . tail) . filter ( (== "HOSTNAME") . head ) . map (T.splitOn "=") . T.lines

postAnalysis :: Seq Vulnerability -> Seq Vulnerability
postAnalysis allvulns = ifoldMapOf itraversed dispatch regrouped
    where
       regrouped = regroupVulnByType allvulns
       dispatch :: VulnGroup -> Seq Vulnerability -> Seq Vulnerability
       dispatch GAuthUnix = analyzeUnixUsers
       dispatch GFS       = analyzeFS regrouped
       dispatch GMisc     = analyzeMisc
       dispatch _         = id

analyzeMisc :: Seq Vulnerability -> Seq Vulnerability
analyzeMisc lst = lst <> wrongSysctl sysctls
    where
        sysctls = lst ^.. folded . _ConfigInformation . _Sysctl

postTarAnalysis :: (UnixVersion
                -> Maybe (Once ([OvalDefinition], HM.HashMap OTestId OFullTest)))
                -> Once [PatchInfo]
                -> Seq ConfigInfo
                -> IO (Seq Vulnerability)
postTarAnalysis dispatchoval xdiag cinfo = do
      rpmvulns <- postRPMAnalysis dispatchoval cinfo
      debvulns <- postDebAnalysis dispatchoval cinfo
      solvulns <- postSolarisAnalysis xdiag cinfo
      return $ postAnalysis (fmap ConfigInformation cinfo <> rpmvulns <> solvulns <> debvulns)

analyzeFile :: (Monad m, MonadIO m)
            => AuditFileType
            -> Once [PatchInfo]
            -> (UnixVersion -> Maybe (Once ([OvalDefinition], HM.HashMap OTestId OFullTest)))
            -> Once (IM.IntMap (T.Text, Day))
            -> FilePath
            -> m (Seq Vulnerability)
analyzeFile tp xdiag dispatchoval okbd fileLocation =
    let posta = postTarAnalysis dispatchoval xdiag
    in  liftIO $ case tp of
                 AuditTarGz   -> runResourceT (analyzeTarGz configExtract fileLocation) >>= posta
                 AuditTar     -> runResourceT (analyzeTar   configExtract fileLocation) >>= posta
                 MBSAReport   -> analyzeMBSA okbd fileLocation
                 MissingKBs   -> analyzeMissingKBs okbd fileLocation
                 WinVBSReport -> analyzeWindowsAudit fileLocation
                 WinAuditTool -> analyzeAuditTools fileLocation >>= posta

analyzeStream :: AuditFileType
              -> Once [PatchInfo]
              -> (UnixVersion -> Maybe (Once ([OvalDefinition], HM.HashMap OTestId OFullTest)))
              -> Once (IM.IntMap (T.Text, Day))
              -> FilePath
              -> BSL.ByteString
              -> IO (Seq Vulnerability)
analyzeStream tp xdiag dispatchoval okbd fileLocation content =
    let posta = postTarAnalysis dispatchoval xdiag
    in  case tp of
          AuditTar     -> runConduit (CL.sourceList (BSL.toChunks content) .| tarAnalyzer configExtract .| CL.foldMap id) >>= posta
          AuditTarGz   -> runConduit (CL.sourceList (BSL.toChunks content) .| CZ.ungzip .| tarAnalyzer configExtract .| CL.foldMap id) >>= posta
          WinVBSReport -> return (Seq.fromList (parseWindowsAudit (BSL.toStrict content)))
          WinAuditTool -> posta (Seq.fromList (parseAuditTool content))
          MBSAReport   -> analyzeMBSAContent okbd fileLocation (BSL.toStrict content)
          MissingKBs   -> analyzeMissingKBsContent okbd fileLocation (BSL.toStrict content)

cficheUsers :: Seq Vulnerability -> ([UnixUser], [UnixUser], [WinUser], [WinUser], M.Map Text [AppUser])
cficheUsers res = ( uprivusers
                  , uotherusers
                  , wprivusers
                  , wotherusers
                  , mempty
                  )
    where
        cinfos = res ^.. folded . _ConfigInformation
        wingroups :: [WinGroup]
        (unixusers, winusers, wingroups) = runfold ((,,) <$> prismFold _ConfUnixUser
                                                         <*> prismFold _ConfWinUser
                                                         <*> prismFold _ConfWinGroup
                                                   ) cinfos
        isPriv u = u ^. uupwd . pwdUid == 0 || not (M.null (u ^. uusudo))
        groupsOfSid :: SID -> [WinGroup]
        groupsOfSid sid = do
            g <- wingroups
            guard (sid `elem` map snd (_wingroupmembers g))
            g : groupsOfSid (_wingroupsid g)
        isWPriv u = any isAdminSID (_winsid u : map _wingroupsid (groupsOfSid (_winsid u)))
        (uprivusers, uotherusers) = partition isPriv unixusers
        (wprivusers, wotherusers) = partition isWPriv winusers

cficheIfaces :: M.Map VulnGroup RegroupedVulnerability -> [(Text, Text, Maybe MAC, Maybe Text)]
cficheIfaces = toListOf (ix GNet . _RNet . _1 . folded . to getvlan)
    where
        getvlan :: NetIf -> (Text, Text, Maybe MAC, Maybe Text)
        getvlan x = (x ^. ifname, described, x ^. ifmac, Nothing)
            where
                described = case x of
                                If4 _ a _ -> toText a
                                If6 _ a _ -> toText a

getAymlFile :: Integral n => FilePath -> n -> FilePath
getAymlFile extrafp aid = extrafp <> "/audit" <> show (fromIntegral aid :: Integer) <> ".yaml"

ficheData :: Seq Vulnerability -> FicheInfo
ficheData res
  = FicheInfo unixversion
              rrs
              packages
              (cficheUsers res)
              (sortBy (flip (comparing fst)) (regrouped ^. ix GFS . _RFS))
              Nothing
              (JMap packageVulnMap)
              (cficheIfaces regrouped)
              latestPatch
              miscVulns
              (buildNetApps (regrouped ^. ix GNet . _RNet . _1) (regrouped ^. ix GNet . _RNet . _2))
              (regrouped ^? ix GInfo . _RV . folded . _ConfigInformation . _Hostname)
    where
        alreadyKnown = [ hasn't (_ConfigInformation . _ConfPass)
                       , hasn't (_ConfigInformation . _ConfShadow)
                       , hasn't (_ConfigInformation . _ConfGroup)
                       , hasn't (_ConfigInformation . _UVersion)
                       , hasn't (_ConfigInformation . _ConfUnixUser)
                       , hasn't (_ConfigInformation . _ConfWinUser)
                       , hasn't (_ConfigInformation . _ConfUnixFile)
                       , hasn't (_ConfigInformation . _ConfUnixFileNG)
                       , hasn't (_ConfigInformation . _BrokenLink)
                       , hasn't (_ConfigInformation . _CIf)
                       , hasn't (_ConfigInformation . _ConfigError)
                       , hasn't (_ConfigInformation . _Sysctl)
                       , hasn't (_ConfigInformation . _SoftwarePackage)
                       , hasn't (_ConfigInformation . _SolPatch)
                       , hasn't (_Vulnerability . _2 . _OutdatedPackage)
                       , hasn't (_Vulnerability . _2 . _VFile)
                       ]
        miscVulns = res ^.. folded . filtered (\r -> all (\c -> c r) alreadyKnown)
        rrs = res ^.. folded . _ConfigInformation . _ConfigError
        fromRes def prm = case res ^.. folded . prm of
                              []  -> def
                              x:_ -> x
        unixversion = fromRes (UnixVersion (Unk "???") []) (_ConfigInformation . _UVersion)
        packages = sort $ mapMaybe getPackageInfo $ F.toList res
        getPackageInfo (Vulnerability s (OutdatedPackage (OP desc installed patchver pubdate _))) = Just (pubdate, s, desc, installed, patchver)
        getPackageInfo _ = Nothing
        regrouped = regroupvulns res
        packageVulnMap = regrouped ^. ix GPackages . _RPack
        latestPatch = if null packages
                          then Nothing
                          else Just $ minimum $ map (view _1) packages

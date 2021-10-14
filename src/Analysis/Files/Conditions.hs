{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}

module Analysis.Files.Conditions where

import Analysis.Common
import Analysis.Types.File
import Analysis.Types.Helpers (safeBS2Text)
import Analysis.Types.Vulnerability
import Control.Applicative
import Control.Lens
import Control.Monad
import qualified Data.ByteString as BSN
import qualified Data.ByteString.Char8 as BS
import qualified Data.CompactMap as CM
import Data.Condition
import qualified Data.Foldable as F
import qualified Data.HashSet as HS
import Data.List
import qualified Data.Map.Strict as M
import Data.Maybe (fromMaybe, mapMaybe)
import qualified Data.Maybe.Strict as S
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Word (Word8)
import GHC.Exts (sortWith)

type UnixFileParse = UnixFileGen BS.ByteString FP

type FP = BS.ByteString

{- Récupéré de posix-paths -}
hasTrailingPathSeparator :: FP -> Bool
hasTrailingPathSeparator x
  | BS.null x = False
  | x == "/" = False
  | otherwise = isPathSeparator $ BSN.last x

dropTrailingPathSeparator :: FP -> FP
dropTrailingPathSeparator x =
  if hasTrailingPathSeparator x
    then BSN.init x
    else x

pathSeparator :: Word8
pathSeparator = 0x2f -- '/'

isPathSeparator :: Word8 -> Bool
isPathSeparator = (== pathSeparator)

dropFileName :: FP -> FP
dropFileName = fst . splitFileName

splitFileNameRaw :: FP -> (FP, FP)
splitFileNameRaw = BSN.breakEnd isPathSeparator

splitFileName :: FP -> (FP, FP)
splitFileName x =
  if BS.null path
    then ("./", file)
    else (path, file)
  where
    (path, file) = splitFileNameRaw x

{- fin récupération -}

data FileRule
  = FilePattern [Pattern FP]
  | NoRule
  | RuleAdd FileRule FileRule
  | RuleCaseP (UnixFileParse -> Bool) (UnixFile -> UnixFile -> FileVuln)
  | RuleCaseF (UnixFileParse -> Bool) (UnixFile -> FileVuln)

decodeFile :: UnixFile -> UnixFileParse
decodeFile = bimap T.encodeUtf8 BS.pack

instance Monoid FileRule where
  mempty = NoRule

instance Semigroup FileRule where
  (<>) = RuleAdd

tfp :: UnixFile -> Text
tfp = T.pack . view filePath

userFiles ::
  -- | User's home directory without trailing "/"
  FP ->
  FileRule
userFiles u =
  FilePattern userfiles
    <> ruleCase
      worldWritable
      (ShouldNotBeWritable "Should only be writable by its owner")
      (\original -> ShouldNotBeWritable (tfp original <> " should only be writable by its owner"))
    <> RuleCaseF worldReadable (ShouldNotBeReadable "Should only be writable by its owner")
  where
    userfiles =
      map
        (E . (u <>))
        [ "/.ssh/id_rsa",
          "/.ssh/id_dsa",
          "/.rhosts",
          "/.shosts",
          "/.ssh/authorized_keys",
          "/.bash_history",
          "/.sh_history"
        ]

cronRule ::
  -- | User name
  BS.ByteString ->
  -- | Command
  FP ->
  FileRule
cronRule user commandpath =
  FilePattern [E commandpath]
    <> ruleCase
      (\f -> not (ownedBy "root" f || ownedBy user f))
      (ShouldBeOwnedBy "root" ("File used in a cron command for user " <> T.pack (show user)))
      (\original -> ShouldBeOwnedBy "root" (tfp original <> " is used in a cron command for user " <> T.pack (show user)))
    <> ruleCase
      worldWritable
      (ShouldNotBeWritable ("File used in a cron command for user " <> T.pack (show user)))
      (\original -> ShouldNotBeWritable (tfp original <> " is used in a cron command for user " <> T.pack (show user)))

defFileRules :: [(Severity, FileRule)]
defFileRules =
  [ ( High,
      FilePattern noReadFiles
        <> ruleCase
          (not . ownedBy "root")
          (ShouldBeOwnedBy "root" "File should only be readable by root")
          (\original -> ShouldBeOwnedBy "root" (tfp original <> " should never be readable except by root"))
        <> ruleCase
          worldWritable
          (ShouldNotBeWritable "This is a sensitive file")
          (\original -> ShouldNotBeWritable (tfp original <> " is a sensitive file"))
        <> RuleCaseF worldReadable (ShouldNotBeReadable "Should only be read by root")
    ),
    ( High,
      FilePattern noWriteFiles
        <> ruleCase
          (not . ownedByPriv)
          (ShouldBeOwnedBy "root" "File should be owned by a secure user")
          (\original -> ShouldBeOwnedBy "root" (tfp original <> " should be owned by a secure user"))
        <> RuleCaseF worldWritable (ShouldNotBeWritable "File should be owned by a secure user")
    ),
    ( Medium,
      RuleCaseF
        (\f -> f ^. filePerms . permsSU && not (isLink f) && not (isSocket f) && not ((f ^. filePath) `HS.member` goodSetuid))
        StrangeSuid
    )
  ]
  where
    ownedByPriv x = x ^. fileUser `elem` ["root", "uucp", "bin", "lp"]

{-
            when (checkCondition (flip match tp) sudoroot ) $ do
                chkd (not . ownedBy "root") (rs $ ShouldBeOwnedBy "root" "sudo root") High
                chkd worldWritable          (rs $ ShouldNotBeWritable    "sudo root") High
            when (checkCondition (flip match tp) sudouser ) $ do
                chkd (not . ownedBy "root") (rs $ ShouldBeOwnedBy "root" "sudo user") Medium
                chkd worldWritable          (rs $ ShouldNotBeWritable    "sudo user") Medium
            unless (  match (P "/dev/") tp
                   || match (P "/devices/") tp
                   || match (P "/selinux/") tp
                   || match (P "/var/lib/ntp/proc/") tp
                   || tp == "/tmp"
                   || tp == "/var/tmp"
                   ) $ do
                chkd (\x -> executable x && worldWritable x && isFile x) (rs $ ShouldNotBeWritable "lastpass") Low
-}
ruleCase :: (UnixFileParse -> Bool) -> (UnixFile -> FileVuln) -> (UnixFile -> UnixFile -> FileVuln) -> FileRule
ruleCase chk filevuln parentvuln = RuleCaseP chk parentvuln <> RuleCaseF chk filevuln

compileRules :: [(Severity, FileRule)] -> [CheckCondition]
compileRules = map snd . sortWith fst . map compileRule

compileRule :: (Severity, FileRule) -> (Severity, CheckCondition)
compileRule (sev, rule) = (sev, cond)
  where
    cond =
      CheckCondition
        (Or patternCond)
        (Or $ map (Pure . fst) $ reverse fileCond)
        (Or $ map (Pure . fst) $ reverse parentCond)
        (foldr mkvf (error "mkvf") $ reverse fileCond)
        (foldr mkvp (error "mkvp") $ reverse parentCond)
    (patternCond, fileCond, parentCond) = foldrule ([], [], []) rule
    foldrule acc (FilePattern ptr) = acc & _1 %~ (<> map Pure ptr)
    foldrule acc NoRule = acc
    foldrule acc (RuleAdd a b) = foldrule (foldrule acc a) b
    foldrule acc (RuleCaseF m v) = acc & _2 %~ ((m, v) :)
    foldrule acc (RuleCaseP m v) = acc & _3 %~ ((m, v) :)
    mkvf (cnd, mkv) curvuln f =
      if cnd (decodeFile f)
        then Vulnerability sev (VFile $ mkv f)
        else curvuln f
    mkvp (cnd, mkv) curvuln c f =
      if cnd (decodeFile f)
        then Vulnerability sev (VFile $ mkv c f)
        else curvuln c f

ownedBy :: Eq a => a -> UnixFileGen a b -> Bool
ownedBy u = (== u) . view fileUser

isLink :: UnixFileGen a b -> Bool
isLink = (== TLink) . view fileType

isFile :: UnixFileGen a b -> Bool
isFile = (== TFile) . view fileType

isSocket :: UnixFileGen a b -> Bool
isSocket = (== TSocket) . view fileType

worldReadable :: UnixFileGen a b -> Bool
worldReadable f = not (isLink f) && view (filePerms . permsOR) f

worldWritable :: UnixFileGen a b -> Bool
worldWritable f = not (isLink f) && not (isSocket f) && view (filePerms . permsOW) f

executable :: UnixFileGen a b -> Bool
executable f =
  f ^. filePerms . permsOX
    || f ^. filePerms . permsUX
    || f ^. filePerms . permsGX

gen2vt :: UnixFileParse -> UnixFile
gen2vt = bimap safeBS2Text BS.unpack

getParent :: FP -> S.Maybe FP
getParent "" = S.Nothing
getParent "/" = S.Nothing
getParent x = S.Just $ dropTrailingPathSeparator $ dropFileName x

data CheckCondition
  = CheckCondition
      { _ccPatternCon :: Condition (Pattern FP),
        _ccFileCon :: Condition (UnixFileParse -> Bool),
        _ccParentcon :: Condition (UnixFileParse -> Bool),
        _ccMkVuln :: UnixFile -> Vulnerability,
        _ccMkVulnP :: UnixFile -> UnixFile -> Vulnerability
      }

data CompiledPatterns
  = CompiledPatterns
      { _cpPrefix :: [FP],
        _cpSuffix :: [FP],
        _cpInfix :: [FP],
        _cpEqua :: [FP],
        _cpResidual :: Condition (Pattern FP)
      }
  deriving (Show, Eq)

-- | Monoid  = or
instance Monoid CompiledPatterns where
  mempty = CompiledPatterns [] [] [] [] (Always False)

instance Semigroup CompiledPatterns where
  CompiledPatterns a1 a2 a3 a4 a5 <> CompiledPatterns b1 b2 b3 b4 b5 = CompiledPatterns (a1 <> b1) (a2 <> b2) (a3 <> b3) (a4 <> b4) (simplifyCond1 $ Or [a5, b5])

compileCondition :: Condition (Pattern FP) -> CompiledPatterns
compileCondition = go . simplifyCond1
  where
    go (Or xs) = foldMap compileCondition xs
    go (Pure n) = case n of
      P x -> CompiledPatterns [x] [] [] [] (Always False)
      I x -> CompiledPatterns [] [] [x] [] (Always False)
      S x -> CompiledPatterns [] [x] [] [] (Always False)
      E x -> CompiledPatterns [] [] [] [x] (Always False)
    go a = CompiledPatterns [] [] [] [] a

-- | Stratégie : on passe d'abord toutes les conditions sur les patterns
-- qui peuvent se résoudre rapidement (tout sauf suffix, infix et combos),
-- et on stocke tous les "infix" pour plus tard.
--
-- On transporte aussi une grosse map des fichiers déjà vérifiés pour ne
-- pas mettre des vulns en doublon (par exemple sur / n'est pas au bon
-- user, ce qui va spammer)
fileCondition :: [CheckCondition] -> CM.CompactMap FP UnixFileParse -> Seq Vulnerability
fileCondition allconds filemap = fchecks <> rchecks
  where
    checkMap :: Vulnerability -> M.Map String Severity -> Maybe (M.Map String Severity)
    checkMap v mp = do
      Vulnerability sev vt <- Just v
      fp <- vt ^? _VFile . vtFile . filePath
      case M.lookup fp mp of
        Nothing -> Just (M.insert fp sev mp)
        Just sev' ->
          if sev' < sev
            then Just (M.insert fp sev mp)
            else Nothing
    appendWithCheckMap :: (UnixFileParse -> Maybe Vulnerability) -> (Seq Vulnerability, M.Map String Severity) -> UnixFileParse -> (Seq Vulnerability, M.Map String Severity)
    appendWithCheckMap mkvuln dropVuln@(curlst, curmp) file = fromMaybe dropVuln $ do
      v <- mkvuln file
      newmp <- checkMap v curmp
      return (curlst Seq.|> v, newmp)
    updateCheckMap :: ([Vulnerability], M.Map String Severity) -> Vulnerability -> ([Vulnerability], M.Map String Severity)
    updateCheckMap dropVuln@(vulnlist, curmp) vuln = fromMaybe dropVuln $ do
      nmp <- checkMap vuln curmp
      return (vuln : vulnlist, nmp)
    (rchecks, _) = F.foldl' (appendWithCheckMap slowChecks) (mempty, vulnFiles) filemap
    slowChecks :: UnixFileParse -> Maybe Vulnerability
    slowChecks curfile = case mapMaybe subcheck remcond of
      (v : _) -> Just v
      _ -> Nothing
      where
        subcheck cond =
          if checkCondition (`match` view filePath curfile) (_ccPatternCon cond)
            then runChecks cond curfile <|> (getParent' curfile >>= runChecksParent cond curfile)
            else Nothing
    -- rem sera la liste des infix
    remcond :: [CheckCondition]
    (remcond, vulnFiles, fchecks) = foldl' firstChecks (mempty, mempty, mempty) allconds
    firstChecks :: ([CheckCondition], M.Map String Severity, Seq Vulnerability) -> CheckCondition -> ([CheckCondition], M.Map String Severity, Seq Vulnerability)
    firstChecks (currem, curcheckedfiles, curchecks) c = (nextrem, newcheckedfiles, curchecks <> Seq.fromList newchecks)
      where
        (newchecks, newcheckedfiles) = foldl' updateCheckMap ([], curcheckedfiles) (prefixChecks <> equalChecks)
        CompiledPatterns p s i e r = compileCondition $ _ccPatternCon c
        nextrem =
          if null s && null i && r == Always False
            then currem
            else c {_ccPatternCon = Or recomposed} : currem
        recomposed = r : map (Pure . I) i <> map (Pure . S) s
        prefixChecks :: [Vulnerability]
        prefixChecks = concat $ mapMaybe (\fp -> exploreFilemap fp <$> CM.getLE fp filemap) p
        equalChecks :: [Vulnerability]
        equalChecks = mapMaybe (\fp -> CM.lookup fp filemap >>= runChecks c) e
        exploreFilemap :: FP -> (Int, UnixFileParse) -> [Vulnerability]
        exploreFilemap ref (startidx, startfile) = goe $ if matchingP startfile then startidx else startidx + 1
          where
            goe i' = case CM.getIndex i' filemap of
              Nothing -> []
              Just f ->
                if not (matchingP f)
                  then []
                  else
                    let nxt = goe (i' + 1)
                     in (runChecks c f ^.. folded) <> nxt
            matchingP f = match (P ref) (f ^. filePath)
    getParent' :: UnixFileParse -> Maybe UnixFileParse
    getParent' = view (from strict) . getParent . view filePath >=> flip CM.lookup filemap
    runChecksParent :: CheckCondition -> UnixFileParse -> UnixFileParse -> Maybe Vulnerability
    runChecksParent c childfile curfile =
      if checkCondition ($ curfile) (_ccParentcon c)
        then Just $ _ccMkVulnP c (gen2vt childfile) (gen2vt curfile)
        else getParent' curfile >>= runChecksParent c childfile
    runChecks :: CheckCondition -> UnixFileParse -> Maybe Vulnerability
    runChecks c curfile =
      if checkCondition ($ curfile) (_ccFileCon c)
        then Just $ _ccMkVuln c $ gen2vt curfile
        else getParent' curfile >>= runChecksParent c curfile

goodSetuid :: HS.HashSet FP
goodSetuid =
  HS.fromList
    [ "/bin/umount",
      "/bin/ping",
      "/bin/su",
      "/bin/mount",
      "/bin/fusermount",
      "/bin/ping6",
      "/sbin/umount.nfs",
      "/sbin/mount.nfs4",
      "/sbin/mount.nfs",
      "/sbin/umount.nfs4",
      "/sbin/pam_timestamp_check",
      "/sbin/mount.ecryptfs_private",
      "/sbin/netreport",
      "/sbin/unix_chkpwd",
      "/usr/sbin/suexec",
      "/usr/sbin/sendmail.sendmail",
      "/usr/sbin/userhelper",
      "/usr/sbin/ccreds_validate",
      "/usr/sbin/usernetctl",
      "/usr/kerberos/bin/ksu",
      "/usr/libexec/utempter/utempter",
      "/usr/libexec/openssh/ssh-keysign",
      "/usr/bin/at",
      "/usr/bin/crontab",
      "/usr/bin/ssh-agent",
      "/usr/bin/locate",
      "/usr/bin/write",
      "/usr/bin/wall",
      "/usr/bin/newgrp",
      "/usr/bin/sudoedit",
      "/usr/bin/chage",
      "/usr/bin/lockfile",
      "/usr/bin/rsh",
      "/usr/bin/chfn",
      "/usr/bin/sudo",
      "/usr/bin/chsh",
      "/usr/bin/rlogin",
      "/usr/bin/passwd",
      "/usr/bin/gpasswd",
      "/usr/bin/rcp",
      "/lib64/dbus-1/dbus-daemon-launch-helper",
      "/usr/bin/screen",
      "/usr/sbin/lockdev",
      "/usr/sbin/sendmail",
      "/usr/sbin/traceroute",
      "/usr/bin/ping",
      "/usr/bin/mail",
      "/usr/bin/expiry",
      "/usr/bin/atop",
      "/usr/bin/cl_status",
      "/media/.hal-mtab-lock",
      "/usr/bin/Xorg",
      "/usr/bin/pkexec",
      "/usr/libexec/polkit-1/polkit-agent-helper-1",
      "/usr/libexec/pt_chown",
      "/root/work/vmware-tools-distrib/lib/bin32/vmware-user-suid-wrapper",
      "/root/work/vmware-tools-distrib/lib/bin64/vmware-user-suid-wrapper",
      "/usr/bin/ksu",
      "/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper",
      "/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper",
      "/usr/bin/staprun",
      "/usr/sbin/fping",
      "/usr/sbin/fping6",
      "/usr/lib/virtualbox/VBoxHeadless",
      "/usr/lib/virtualbox/VBoxNetAdpCtl",
      "/usr/lib/virtualbox/VBoxNetDHCP",
      "/usr/lib/virtualbox/VBoxSDL",
      "/usr/lib/virtualbox/VBoxVolInfo",
      "/usr/lib/virtualbox/VirtualBox",
      -- solaris ...
      "/etc/lp/alerts/printer",
      "/usr/bin/atq",
      "/usr/bin/atrm",
      "/usr/bin/cancel",
      "/usr/bin/cdrw",
      "/usr/bin/chkey",
      "/usr/bin/ct",
      "/usr/bin/eject",
      "/usr/bin/fdformat",
      "/usr/bin/login",
      "/usr/bin/lp",
      "/usr/bin/lpset",
      "/usr/bin/lpstat",
      "/usr/bin/mailq",
      "/usr/bin/pfexec",
      "/usr/bin/pppd",
      "/usr/bin/rdist",
      "/usr/bin/rmformat",
      "/usr/bin/sparcv9/newtask",
      "/usr/bin/sparcv9/uptime",
      "/usr/bin/sparcv9/w",
      "/usr/bin/su",
      "/usr/bin/volrmmount",
      "/usr/dt/bin/dtaction",
      "/usr/dt/bin/dtappgather",
      "/usr/dt/bin/dtfile",
      "/usr/dt/bin/dtprintinfo",
      "/usr/dt/bin/dtsession",
      "/usr/dt/bin/sdtcm_convert",
      "/usr/lib/acct/accton",
      "/usr/lib/cacao/lib/tools/cacaocsc",
      "/usr/lib/fbconfig/SUNWifb_config",
      "/usr/lib/fbconfig/SUNWjfb_config",
      "/usr/lib/fbconfig/SUNWnfb_config",
      "/usr/lib/fbconfig/SUNWpfb_config",
      "/usr/lib/fs/ufs/quota",
      "/usr/lib/fs/ufs/ufsdump",
      "/usr/lib/fs/ufs/ufsrestore",
      "/usr/lib/gnome-suspend",
      "/usr/lib/lp/bin/netpr",
      "/usr/lib/print/lpd-port",
      "/usr/lib/pt_chmod",
      "/usr/lib/ssh/ssh-keysign",
      "/usr/lib/utmp_update",
      "/usr/lib/webconsole/adminverifier",
      "/usr/lib/webconsole/pamverifier",
      "/usr/openwin/bin/sys-suspend",
      "/usr/openwin/bin/xlock",
      "/usr/openwin/bin/xscreensaver",
      "/usr/sbin/allocate",
      "/usr/sbin/deallocate",
      "/usr/sbin/list_devices",
      "/usr/sbin/lpmove",
      "/usr/sbin/m64config",
      "/usr/sbin/ping",
      "/usr/sbin/pmconfig",
      "/usr/sbin/sacadm",
      "/usr/sbin/smpatch",
      "/usr/sbin/sparcv9/whodo",
      "/usr/vmsys/bin/chkperm",
      "/usr/xpg4/bin/at",
      "/usr/bin/cu",
      "/usr/bin/tip",
      "/usr/bin/uucp",
      "/usr/bin/uuglist",
      "/usr/bin/uuname",
      "/usr/bin/uustat",
      "/usr/bin/uux",
      "/usr/lib/uucp/remote.unknown",
      "/usr/lib/uucp/uucico",
      "/usr/lib/uucp/uusched",
      "/usr/lib/uucp/uuxqt"
    ]

noReadFiles :: [Pattern FP]
noReadFiles =
  [ P "/etc/shadow",
    P "/etc/crypttab",
    P "/etc/gshadow",
    P "/etc/ntp.keys",
    P "/var/log/auth.log",
    P "/var/log/crond.log",
    P "/var/log/daemon.log",
    P "/var/log/errors.log",
    P "/var/log/everything.log",
    P "/var/log/iptables.log",
    P "/var/log/kern.log",
    P "/var/log/kernel.log",
    P "/var/log/messages.log",
    P "/var/log/syslog.log",
    P "/var/log/user.log",
    E "/etc/krb5.keytab"
  ]

noWriteFiles :: [Pattern FP]
noWriteFiles =
  [ P "/etc/init.d",
    P "/etc/conf.d",
    P "/etc/rc.",
    P "/etc/xinetd.d",
    P "/etc/ld.so.conf",
    P "/etc/cron.",
    P "/var/log/auth.log",
    P "/var/log/crond.log",
    P "/var/log/daemon.log",
    P "/var/log/errors.log",
    P "/var/log/everything.log",
    P "/var/log/iptables.log",
    P "/var/log/kern.log",
    P "/var/log/kernel.log",
    P "/var/log/messages.log",
    P "/var/log/syslog.log",
    P "/var/log/user.log",
    P "/bin",
    P "/usr/bin",
    P "/usr/local/bin",
    P "/sbin",
    P "/usr/sbin",
    P "/usr/local/sbin",
    P "/lib",
    P "/usr/lib",
    P "/usr/local/lib",
    P "/usr/sfw",
    P "/etc/sysconfig",
    P "/etc/udev",
    P "/etc/hosts",
    E "/etc/group",
    E "/etc/inittab",
    E "/etc/fstab",
    E "/etc/profile",
    E "/etc/sudoers",
    E "/etc/crypttab",
    E "/etc/gshadow"
  ]

{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
module Analysis.WindowsAudit
 ( analyzeWindowsAudit
 , analyzeAuditTools
 , parseWindowsAudit
 , parseAuditTool
 ) where

import qualified Data.Text as T
import qualified Data.Text.Read as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Textual as T
import qualified Data.Vector as V
import qualified Data.Sequence as Seq
import qualified Data.Map.Strict as M
import qualified Data.Set as S
import Data.Text (Text)
import Data.Sequence (Seq)
import Data.Monoid
import Data.List (nub)
import Data.Word (Word8)
import Data.Char
import Control.Lens
import Data.Bits (popCount)
import Network.IP.Addr
import Data.Maybe
import Safe

import Data.PrismFilter
import Analysis.Common
import Analysis.Types
import AuditTool

data UserAnalysis = WUser Text Bool Bool SID
                  | WGroup Text Text SID
                  | WProblem Text
                  deriving Show

makePrisms ''UserAnalysis

analyzeAuditTools :: FilePath -> IO (Seq ConfigInfo)
analyzeAuditTools = fmap (Seq.fromList . parseAuditTool) .  BSL.readFile

analyzeWindowsAudit :: FilePath -> IO (Seq Vulnerability)
analyzeWindowsAudit = fmap (Seq.fromList . parseWindowsAudit) . BS.readFile

parseWindowsAudit :: BS.ByteString -> [Vulnerability]
parseWindowsAudit = mkvlns
                  . map (T.break (not . isAsciiUpper))
                  . T.lines
                  . T.decodeLatin1
    where
        mkvlns x = lineVulns x ++ userAnalysis x
        lineVulns = mapMaybe (uncurry parseLine)
                  . filter importantInfo
                  . map (_2 %~ cleanLine)
                  . filter (not . ignoredCategory . fst)
        importantInfo ("INFO", x:_) = x `elem` [ "COMPNAME"
                                               , "CAPTION"
                                               , "CAPTION2"
                                               , "VERSION"
                                               , "OSADDRESSWIDTH"
                                               ]
        importantInfo _ = True

userAnalysis :: [(Text, Text)] -> [Vulnerability]
userAnalysis = analyzeUser . arrangeInfo . mapMaybe (toUser . (_2 %~ cleanLine))
    where
        getSid t = do
            elems <- tailMay (T.splitOn "-" t)
            ielems <- mapM text2Int elems
            case ielems of
                (rev : auth : sauths) -> return (SID (fromIntegral rev) (fromIntegral auth) (map fromIntegral sauths))
                _ -> Nothing
        toUser ("USER", [nm, sid, dis, loc]) = WUser nm <$> db dis <*> db loc <*> getSid sid
        toUser ("GROUP", [sid, gn, uname]) = WGroup gn (cleanu uname) <$> getSid sid
        toUser ("USER", x) = Just $ WProblem ("Invalid user information: " <> T.pack (show x))
        toUser ("GROUP", x) = Just $ WProblem ("Invalid group information: " <> T.pack (show x))
        toUser _ = Nothing
        cleanu x = case T.break (== '\\') x of
                       (r,"") -> r
                       (_,r) -> T.tail r
        db "Vrai" = Just True
        db "Faux" = Just False
        db "True" = Just True
        db "False" = Just False
        db _ = Nothing
        analyzeUser :: ( [(Text, Bool, Bool, SID)], [(Text, Text, SID)], [Text] ) -> [Vulnerability]
        analyzeUser (userlist, grouplist, problemlist) = mapMaybe miscErr problemlist ++ map userinfo userlist ++ groupinfo
            where
                userinfo (username, disabled, locked, sid) = ConfigInformation (ConfWinUser
                            ( WinUser username
                                      sid
                                      (if disabled then S.singleton UAC_ACCOUNTDISABLE else mempty <> if locked then S.singleton UAC_LOCKOUT else mempty)
                                      Nothing
                            )
                         )
                groupinfo = do
                    ((gname, gsid), gusers) <- M.toList groupmap
                    return $ ConfigInformation $ ConfWinGroup $ WinGroup gname gsid Nothing (map (\u -> (u, getUserSID u)) gusers)
                makeSID :: Text -> SID
                makeSID = SID 1 111 . map fromIntegral . BS.unpack . T.encodeUtf8
                getUserSID :: Text -> SID
                getUserSID u = M.findWithDefault (makeSID u) u usermap
                usermap :: M.Map Text SID
                usermap = M.fromList (map (\(u, _, _, sid) -> (u, sid)) userlist ++ map (\(g,_,s) -> (g,s)) grouplist)
                groupmap :: M.Map (Text, SID) [Text]
                groupmap = nub <$> M.fromListWith (++) (map (\(groupname, username, groupsid) -> ((groupname, groupsid), [username])) grouplist)
        arrangeInfo :: [UserAnalysis] -> ( [(Text, Bool, Bool, SID)], [(Text, Text, SID)], [Text] )
        arrangeInfo = runfold ((,,) <$> prismFold _WUser <*> prismFold _WGroup <*> prismFold _WProblem)

ignoredCategory :: Text -> Bool
ignoredCategory = flip elem [ "BEGIN"
                            , "END"
                            , "LOGAPPERROR"
                            , "LOGAPPERRORGPO"
                            , "LOGGEDUSER"
                            , "LOGSRVSTATE"
                            , "MAJ"
                            , "SCHEDLGU"
                            , "DRV"
                            , "CERT"
                            , "CWSCONFIG"
                            , "CWDEBUG"
                            , "CWTEMP"
                            , "NETWORKADAPTER"
                            , "EVT"
                            , "COM"
                            , "STEP"
                            , "PERSIST"
                            , "LOGBUGCHECK"
                            , "CWMINIDUMP"
                            , "SCHEDTASK"
                            , "PRODVER"
                            , "USER"
                            , "GROUP"
                            ]

cleanLine :: Text -> [Text]
cleanLine = T.splitOn "\t" . T.strip

mkerr :: Text -> [Text] -> Maybe Vulnerability
mkerr t l = miscErr (t <> ": " <> T.intercalate "\t" l)

miscErr :: Text -> Maybe Vulnerability
miscErr = Just . ConfigInformation . ConfigError . MiscError

parseWindowsVersion :: Text -> Maybe UnixVersion
parseWindowsVersion p =
    case p of
        "Windows 7 Professional Service Pack 1" -> Just (UnixVersion (WindowsClient "7 pro") [1])
        "Windows Server 2008 R2 Standard Service Pack 1" -> Just (UnixVersion (WindowsServer "2008 R2") [1])
        "Microsoft Windows 7 Professionnel" -> Just (UnixVersion (WindowsClient "7 pro") [])
        "Microsoft Windows XP Service Pack 2" -> Just (UnixVersion (WindowsClient "XP") [2])
        "Microsoft® Windows Vista\153 Professionnel" -> Just (UnixVersion (WindowsClient "Vista pro") [])
        _ -> Nothing

mkNetif :: Text -> Text -> Text -> Either Text NetIf
mkNetif mac ip mask = If4 <$> pure mac <*> mnet <*> pure mmac
    where
        eparse t x = maybe (Left (t <> ": " <> x)) Right $ T.maybeParsed $ T.parseText x
        mnet = net4Addr <$> eparse "Could not parse IP" ip <*> (fromIntegral . popCount . isIP4 <$> eparse "Could not parse mask" mask)
        isIP4 :: IP4 -> IP4
        isIP4 = id
        hexparse :: Text -> Maybe Word8
        hexparse t = case T.hexadecimal t of
                         Right (x, "") -> Just x
                         _ -> Nothing
        mmac = MAC . V.fromList <$> mapM hexparse (T.splitOn ":" mac)

miscVuln :: Severity -> Text -> Maybe Vulnerability
miscVuln s = Just . Vulnerability s . MiscVuln

miscInfo :: Text -> Maybe Vulnerability
miscInfo = Just . ConfigInformation . MiscInfo

cinfo :: ConfigInfo -> Maybe Vulnerability
cinfo = Just . ConfigInformation

parseLine :: Text -> [Text] -> Maybe Vulnerability
parseLine "PRODUCT" ("UNINSTALL"   : package : version : _) = cinfo (SoftwarePackage (Package package version WindowsInstall))
parseLine "PRODUCT" ("UNINSTALL"   : package : _)           = cinfo (SoftwarePackage (Package package ""      WindowsInstall))
parseLine "PRODUCT" ("UNINSTALL64" : package : version : _) = cinfo (SoftwarePackage (Package package version WindowsInstall))
parseLine "PRODUCT" ("UNINSTALL64" : package : _)           = cinfo (SoftwarePackage (Package package ""      WindowsInstall))
parseLine "PRODUCT" ("PRODUCT"     : package : version : _) = cinfo (SoftwarePackage (Package package version WindowsInstall))
parseLine "PRODUCT" l = mkerr "Bad product line" l
parseLine "INFO" ["COMPNAME", n] = case T.splitOn "\\" n of
                                       [_,b] -> cinfo (Hostname b)
                                       _ -> miscErr ("Bad computer name: " <> n)
parseLine "INFO" [cap, n] | cap == "CAPTION" || cap == "CAPTION2" = maybe (miscErr ("Could not decypher windows version: " <> n)) (cinfo . UVersion) (parseWindowsVersion n)
parseLine "INFO" ["VERSION",l] = cinfo $ KernelVersion l
parseLine "INFO" ["OSADDRESSWIDTH",l] = cinfo $ Architecture l
parseLine "INFO" l = mkerr "Bad info line" l
parseLine "DLL" [path, version] = cinfo (SoftwarePackage (Package path version WindowsDLL))
parseLine "DLL" [path] = cinfo (SoftwarePackage (Package path "?" WindowsDLL))
parseLine "DLL" l = mkerr "Bad DLL line" l
parseLine "IPCONFIG" (mac : ip : mask : _) = either miscErr (cinfo . CIf) (mkNetif mac ip mask)
parseLine "IPCONFIG" l = mkerr "Bad IPCONFIG" l
parseLine "SECU" [a,b] = checkSecu a (T.strip b)
parseLine "SECU" l = mkerr "Bad SECU" l
parseLine "SRV" [sname, _, _, identity, path] | "C:\\Windows\\" `T.isPrefixOf` path = Nothing
                                              | otherwise = miscInfo ("Unknown service " <> sname <> ", running as " <> identity <> ", and located at " <> path)
parseLine cat y = mkerr cat y

checkSecu :: Text -> Text -> Maybe Vulnerability
checkSecu "LMLEVEL" "0" = miscVuln High "lmcompatibilitylevel is 0. Clients use LM and NTLM authentication, but they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication."
checkSecu "LMLEVEL" "1" = miscVuln High "lmcompatibilitylevel is 1. Clients use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication."
checkSecu "LMLEVEL" "2" = miscVuln Medium "lmcompatibilitylevel is 2. Clients use only NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication."
checkSecu "LMLEVEL" "3" = miscVuln Medium "lmcompatibilitylevel is 3. Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication."
checkSecu "LMLEVEL" "4" = miscVuln Low "lmcompatibilitylevel is 4. Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2."
checkSecu "LMLEVEL" "5" = miscInfo "lmcompatibilitylevel is 5. Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2."
checkSecu "NOLMHASH" "1" = miscInfo "nolmhash is set"
checkSecu "NOLMHASH" "0" = miscVuln Medium "LM hashes are used"
checkSecu "EVERYONEINCLUDEANONYMOUS" "1" = miscVuln Low "Everyone includes anonymous"
checkSecu "EVERYONEINCLUDEANONYMOUS" "0" = miscInfo "Anonymous is not in the everyone group"
checkSecu "RESTRICTANONYMOUS" "1" = miscVuln Medium "RestrictAnonymous is not set"
checkSecu "RESTRICTANONYMOUS" "0" = miscInfo "RestrictAnonymous is set"
checkSecu "RESTRICTANONYMOUSSAM" "1" = miscVuln Medium "RestrictAnonymousSam is not set"
checkSecu "RESTRICTANONYMOUSSAM" "0" = miscInfo "RestrictAnonymousSam is set"
checkSecu "NULLSESSIONPIPES" pipe = miscVuln Low ("Null session pipe: " <> pipe)
checkSecu "NULLSESSIONSHARES" pipe = miscVuln Low ("Null session share: " <> pipe)
checkSecu "AUDITBASEOBJECTS" "0" = miscVuln Low "Base objects are not audited"
checkSecu "AUDITBASEOBJECTS" "1" = miscInfo "Base objects are audited"
checkSecu "AUDITFULLPRIV" "0" = miscVuln Low "Backup and restore privileges are not audited"
checkSecu "AUDITFULLPRIV" "1" = miscInfo "Backup and restore privileges are audited"
checkSecu "WKSENABLESECURITYSIGNATURE" "0" = miscVuln High "Client SMB signatures are not enabled"
checkSecu "WKSENABLESECURITYSIGNATURE" "1" = miscInfo "Client SMB signatures are enabled"
checkSecu "WKSREQUIRESECURITYSIGNATURE" "0" = miscVuln Medium "Client SMB signatures are not required"
checkSecu "WKSREQUIRESECURITYSIGNATURE" "1" = miscInfo "Client SMB signatures are required"
checkSecu "SEALSECURECHANNEL" "0" = miscVuln High "Secure channel traffic is NOT encrypted"
checkSecu "SEALSECURECHANNEL" "1" = miscInfo "Secure channel traffic is encrypted"
checkSecu "REQUIRESIGNORSEALSECURECHANNEL" "0" = miscVuln High "Secure channel traffic is not required to be signed or sealed"
checkSecu "REQUIRESIGNORSEALSECURECHANNEL" "1" = miscInfo "Secure channel traffic is required to be signed or sealed"
checkSecu "SIGNSECURECHANNEL" "0" = miscVuln High "Secure channel traffic is not signed"
checkSecu "SIGNSECURECHANNEL" "1" = miscInfo "Secure channel traffic is signed"
checkSecu "REQUIRESTRONGKEY" "0" = miscVuln High "The trusted domain controller is not required to compute a strong key"
checkSecu "REQUIRESTRONGKEY" "1" = miscInfo "The trusted domain controller is required to compute a strong key"
checkSecu "DRIVERSIGNINGPOLICY" "0" = miscVuln High "Drivers signatures are not checked!"
checkSecu "DRIVERSIGNINGPOLICY" "1" = miscVuln Medium "Drivers signatures are not checked by the user"
checkSecu "DRIVERSIGNINGPOLICY" "2" = miscInfo "Drivers signatures are checked"
checkSecu "SRVENABLESECURITYSIGNATURE" "0" = miscVuln High "Server SMB signatures are not enabled"
checkSecu "SRVENABLESECURITYSIGNATURE" "1" = miscInfo "Server SMB signatures are enabled"
checkSecu "SYSSTARTOPT" "NOEXECUTE=ALWAYSON" = miscInfo "DEP is always on"
checkSecu "SYSSTARTOPT" "NOEXECUTE=OPTOUT" = miscInfo "DEP is opt out"
checkSecu "SYSSTARTOPT" "NOEXECUTE=OPTIN" = miscVuln Low "DEP is opt in"
checkSecu "SYSSTARTOPT" "NOEXECUTE=ALWAYSOFF" = miscVuln High "DEP is off"
checkSecu "SCHEDLOGPATH" x = miscInfo ("Scheduler log path: " <> x)
checkSecu "SCHEDPATH" x = miscInfo ("Task folder: " <> x)
checkSecu "SCHEDLOGSIZE" x = miscInfo ("Scheduler log size: " <> x)
checkSecu "AUTORUN" "255" = miscInfo "Autoplay is disabled for all drives"
checkSecu "AUTORUN" x = miscVuln High ("Autoplay is enabled for some drives: " <> x)
checkSecu "UACADMINBEHAVIOR" "0" = miscVuln Medium "No UAC for administrators"
checkSecu "UACADMINBEHAVIOR" "1" = miscInfo "UAC dialog asks for credentials on the secure desktop"
checkSecu "UACADMINBEHAVIOR" "2" = miscVuln Low "UAC dialog set to permit/deny on the secure desktop"
checkSecu "UACADMINBEHAVIOR" "3" = miscVuln (CVSS 1) "UAC dialog asks for credential"
checkSecu "UACADMINBEHAVIOR" "4" = miscVuln Low "UAC dialog set to permit/deny"
checkSecu "UACADMINBEHAVIOR" "5" = miscVuln (CVSS 0.5) "UAC dialog set to permit/deny for non-windows binaries on the secure desktop"
checkSecu "UACUSERBEHAVIOR" "0" = miscInfo "UAC elevations denied for users"
checkSecu "UACUSERBEHAVIOR" "3" = miscVuln (CVSS 1)   "UAC elevations for users ask for credentials on the secure desktop"
checkSecu "UACUSERBEHAVIOR" "1" = miscVuln (CVSS 1.5) "UAC elevations for users ask for credentials"
checkSecu "UACREMOTEFORLOCALACCOUNTS" "1" = miscVuln High "Remote users have a high privilege token"
checkSecu "UACREMOTEFORLOCALACCOUNTS" "0" = miscInfo "Remote users have a filtered token"
checkSecu "UACFORADMINS" "1" = miscInfo "UAC enabled for admins"
checkSecu "UACFORADMINS" "0" = miscVuln Medium "UAC disabled for admins"
checkSecu "DEP" "1" = miscInfo "DEP is always on"
checkSecu "DEP" "3" = miscInfo "DEP is opt out"
checkSecu "DEP" "2" = miscVuln Low "DEP is opt in"
checkSecu "DEP" "0" = miscVuln High "DEP is off"
checkSecu "CACHEDLOGON" x = miscInfo ("Cached domain credentials: " <> x)
checkSecu a b = mkerr "Bad SECU" [a,b]

module Analysis.Sssd (anaSssd) where

import Analysis.Common
import Analysis.Types.ConfigInfo
import Analysis.Types.Helpers (CError (..), safeBS2Text)
import Analysis.Types.UnixUsers
import Control.Applicative
import Control.Dependency
import Control.Lens
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.HashMap.Strict as HM
import Data.List (foldl')
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Serialize.Tdb
import qualified Data.Set as S
import Data.Text (Text)
import qualified Data.Text as T

data TdbData
  = UID Int Text
  | GID Int [Text]
  | GRP Int Text
  | RAW ConfigInfo
  | Uninteresting
  | UserInfo
      Text -- name
      Int -- uidNumber
      Int -- lastCachedPasswordChange
      Text -- gecos
      Int -- gidNumber
      Text -- cachedPassword
      Text -- homeDirectory
      Text -- loginShell
  deriving (Show)

tdbData2Config :: [TdbData] -> [ConfigInfo]
tdbData2Config = fixgroups . foldl' (flip t') ([], [], [])
  where
    fixgroups (cfg, grpn, gids) = cfg <> map ConfGroup grps
      where
        nmmap = HM.fromList gids
        grps = map mkGroup grpn
        mkGroup (gid, members) = GroupEntry (nmmap ^. at gid . non (T.pack (show gid))) gid (S.fromList (map mkMember members))
        mkMember x = case "name=" `T.stripPrefix` x of
          Just l -> T.takeWhile (/= ',') l
          Nothing -> x
    t' (RAW c) (cfg, grpn, gids) = (c : cfg, grpn, gids)
    t' Uninteresting x = x
    t' (UID _ _) x = x
    t' (GID gid lst) (cfg, grpn, gids) = (cfg, (gid, lst) : grpn, gids)
    t' (GRP gid nm) (cfg, grpn, gids) = (cfg, grpn, (gid, nm) : gids)
    t' (UserInfo nm uid lchange gecos gid pwd home shell) (cfg, grpn, gids) = (ConfPass pwdentry : ConfShadow shdentry : cfg, grpn, gids)
      where
        pwdentry = PasswdEntry nm "" uid gid gecos home shell
        shdentry = ShadowEntry nm (SHash pwd) (Just (lchange `div` 1000000)) Nothing Nothing Nothing Nothing Nothing

anaSssd :: Analyzer (Seq ConfigInfo)
anaSssd = analyzeTdb <$> require ["more/var/lib/sss/db/cache_default.ldb"]

parseError :: String -> ConfigInfo
parseError rr = ConfigError (ParsingError "more/var/lib/sss/db/cache_default.ldb" rr Nothing)

analyzeTdb :: BS.ByteString -> Seq ConfigInfo
analyzeTdb x = case tdbEntries x of
  Left rr -> return (parseError ("analyzeTdb " <> rr))
  Right entries -> Seq.fromList $ tdbData2Config $ map analyzeEntry entries

analyzeEntry :: BS.ByteString -> TdbData
analyzeEntry x = case parseElems x of
  Left rr -> RAW (parseError ("analyzeEntry " <> rr))
  Right (k, v) -> analyzeKV k v

analyzeKV :: BS.ByteString -> HM.HashMap BS.ByteString (HM.HashMap BS.ByteString [BS.ByteString]) -> TdbData
analyzeKV k v
  | HM.null vflat = Uninteresting
  | otherwise = case filterout <|> uid <|> user <|> gid <|> grp of
    Just s -> s
    Nothing -> RAW (parseError ("analyzeKV " <> show (k, vflat)))
  where
    vflat = mconcat $ HM.elems v
    tk = safeBS2Text k
    getTxt idx = vflat ^? ix idx . ix 0 . to safeBS2Text
    getInt idx = getTxt idx >>= text2Int
    uid = UID <$> (T.stripPrefix "DN=@INDEX:UIDNUMBER:" tk >>= text2Int) <*> getTxt "@IDX"
    gid = GID <$> (T.stripPrefix "DN=@INDEX:GIDNUMBER:" tk >>= text2Int) <*> (map safeBS2Text <$> (vflat ^? ix "@IDX"))
    grp = do
      oc <- getTxt "objectClass"
      guard (oc == "group")
      GRP <$> getInt "gidNumber" <*> getTxt "name"
    user =
      UserInfo <$> getTxt "name"
        <*> getInt "uidNumber"
        <*> getInt "lastCachedPasswordChange"
        <*> getTxt "gecos"
        <*> getInt "gidNumber"
        <*> getTxt "cachedPassword"
        <*> getTxt "homeDirectory"
        <*> getTxt "loginShell"
    filterout
      | ":ORIGINALDN:" `T.isInfixOf` tk = Just Uninteresting
      | ":DATAEXPIRETIMESTAMP:" `T.isInfixOf` tk = Just Uninteresting
      | ":LASTUPDATE:" `T.isInfixOf` tk = Just Uninteresting
      | "DN=@INDEX:NAME:" `T.isPrefixOf` tk = Just Uninteresting
      | "DN=@INDEX:@IDXONE" `T.isPrefixOf` tk = Just Uninteresting
      | "DN=@INDEX:OBJECTCLASS:USER" == tk = Just Uninteresting
      | "DN=@MODULES" == tk = Just Uninteresting
      | "DN=@ATTRIBUTES" == tk = Just Uninteresting
      | "DN=@BASEINFO" == tk = Just Uninteresting
      | "DN=@INDEXLIST" == tk = Just Uninteresting
      | "DN=@INDEX:CN:SYSDB" == tk = Just Uninteresting
      | "DN=CN=SYSDB" == tk = Just Uninteresting
      | "DN=CN=DEFAULT,CN=SYSDB" == tk = Just Uninteresting
      | "DN=@INDEX:CN:DEFAULT" == tk = Just Uninteresting
      | "DN=CN=USERS,CN=DEFAULT,CN=SYSDB" == tk = Just Uninteresting
      | "DN=@INDEX:CN:USERS" == tk = Just Uninteresting
      | "DN=CN=GROUPS,CN=DEFAULT,CN=SYSDB" == tk = Just Uninteresting
      | "DN=@INDEX:CN:GROUPS" == tk = Just Uninteresting
      | "DN=@INDEX:OBJECTCLASS:GROUP" == tk = Just Uninteresting
      | otherwise = Nothing

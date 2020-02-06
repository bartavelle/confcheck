{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Rank2Types        #-}
{-# LANGUAGE TupleSections     #-}
-- https://www.redhat.com/security/data/metrics/

module Analysis.Oval where

import           Control.Applicative
import           Control.Lens
import           Control.Monad
import qualified Data.ByteString                  as BS
import qualified Data.ByteString.Char8            as BS8
import           Data.DebianVersion
import qualified Data.HashMap.Strict              as HM
import           Data.List                        (intercalate)
import qualified Data.Map.Strict                  as M
import           Data.Maybe                       (fromMaybe, mapMaybe)
import qualified Data.Serialize                   as S
import qualified Data.Text                        as T
import qualified Data.Text.Encoding               as T
import           Data.Time.Calendar
import           Debug.Trace                      (trace)
import           Text.Regex.PCRE.ByteString.Utils

import           Analysis.Common
import           Analysis.Types.Package
import           Analysis.Types.Unix
import           Analysis.Types.Vulnerability
import           Data.Condition
import           Data.Oval

import           Prelude

epoch :: Day
epoch = fromGregorian 1970 1 1

getPackageinfo :: T.Text -> Maybe SoftwarePackage
getPackageinfo x = case reverse (T.splitOn "-" x) of
                       (v2 : v1 : vn) -> let v = v1 <> "-" <> v2
                                         in Just $ Package (T.intercalate "-" (reverse vn)) v PRPM
                       _ -> Nothing

defaultDay :: T.Text -> Day
defaultDay t = case preview (ix 1) (T.splitOn "-" t) >>= text2Int of
                   Just y  -> fromGregorian (fromIntegral y) 1 1
                   Nothing -> epoch

loadOvalSerialized :: FilePath -> IO ([OvalDefinition], HM.HashMap OTestId OFullTest)
loadOvalSerialized f = do
    cnt <- BS.readFile f
    case S.decode cnt of
        Right (r, l) -> return (r, HM.fromList l)
        Left rr      -> error ("loadOvalSerialized: " ++ rr)

-- ^ Le paramètre des packages debians est un peu particulier, car les
-- fichiers oval se basent sur le nom du package *source*
ovalRuleMatchedDEB :: UnixVersion
                   -> T.Text -- architecture
                   -> M.Map T.Text (T.Text, DebianVersion) -- key = source name, fst = package name
                   -> HM.HashMap OTestId OFullTest
                   -> OvalDefinition
                   -> (Bool, [(T.Text, DebianVersion)])
ovalRuleMatchedDEB uversion arch debs tests = fmap (mapMaybe (strength . fmap (preview _Left))) . ovalRuleMatched uversion arch debs mempty tests

strength :: Functor f => (a, f b) -> f (a,b)
strength (a, f) = (a,) <$> f

ovalRuleMatchedRPM :: UnixVersion
                   -> T.Text -- architecture
                   -> M.Map T.Text RPMVersion
                   -> HM.HashMap OTestId OFullTest
                   -> OvalDefinition
                   -> (Bool, [(T.Text, RPMVersion)])
ovalRuleMatchedRPM uversion arch rpms tests = fmap (mapMaybe (strength . fmap (preview _Right))) . ovalRuleMatched uversion arch mempty rpms tests

ovalRuleMatched :: UnixVersion
                -> T.Text -- architecture
                -> M.Map T.Text (T.Text, DebianVersion) -- key = source name, fst = package name
                -> M.Map T.Text RPMVersion
                -> HM.HashMap OTestId OFullTest
                -> OvalDefinition
                -> (Bool, [(T.Text, Either DebianVersion RPMVersion)])
ovalRuleMatched (UnixVersion _ uver ) arch debs rpms tests = tolst . matchingConditions check' . view ovalCond
    where
        tolst Nothing    = (False, [])
        tolst (Just lst) = (True, concat lst)
        check' testid = HM.lookup testid tests >>= runtest
            where
                runtest :: OFullTest -> Maybe [(T.Text, Either DebianVersion RPMVersion)]
                runtest (OFullTest object ostp) = runOpTest object ostp
                runOpTest object opr
                  = case opr of
                      AndStateOp a b -> (<>) <$> runOpTest object a <*> runOpTest object b
                      OvalStateOp testtype operation ->
                        case testtype of
                          SignatureKeyId _ -> Just []
                          IVersion v | operation == Equal ->
                            if uver == v
                              then Just []
                              else Nothing
                          Version v | operation == Equal ->
                            let v' = T.intercalate "." (map (T.pack . show) uver)
                            in  if v' == v
                                  then Just []
                                  else Nothing
                          Version v | operation == PatternMatch ->
                            case compile' compBlank execBlank (T.encodeUtf8 v) of
                              Left _ -> error ("Could not compile this regexp: " <> show v)
                              Right regexp -> case execute' regexp (BS8.pack (intercalate "." (map show uver))) of
                                                Right (Just _) -> Just []
                                                Right Nothing -> Nothing
                                                Left rr -> error ("Could not apply this regexp: " <> show v <> ": " <> show rr)
                          RpmState v | operation == GreaterThanOrEqual -> do
                            rv <- M.lookup object rpms
                            guard (rv >= v)
                            return [(object, Right v)]
                          RpmState v | operation == LessThan -> do
                            rv <- M.lookup object rpms
                            guard (rv < v)
                            return [(object, Right v)]
                          Exists | operation == Equal -> ([] <$ M.lookup object rpms) <|> ([] <$ M.lookup object debs)
                          DpkgState msourcename rawversion | operation == LessThan -> do
                            v <- either (const Nothing) Just (parseDebianVersion rawversion)
                            let sourcename = fromMaybe object msourcename
                            (packagename, rv) <- sourcename `M.lookup` debs
                            guard (rv < v)
                            return [(packagename, Left v)]
                          TTBool b _ -> [] <$ guard b
                          Arch architectures | operation == PatternMatch ->
                            case compile' compBlank execBlank (T.encodeUtf8 architectures) of
                              Left _ -> error ("Could not compile this regexp: " <> show architectures)
                              Right regexp -> case execute' regexp (T.encodeUtf8 arch) of
                                                Right (Just _) -> Just []
                                                Right Nothing -> Nothing
                                                Left rr -> error ("Could not apply this regexp: " <> show architectures <> ": " <> show rr)
                          Arch architecture | operation == Equal ->
                            if arch == architecture
                              then Just []
                              else Nothing
                          UnameIs _ | operation == Equal -> pure [] -- TODO, handle this
                          _ -> error ("runtest: " <> show (object, testtype, operation))

enrichOval :: M.Map T.Text (Day, Severity) -> [OvalDefinition] -> [OvalDefinition]
enrichOval cve = map addTime
    where
        findCveInRef d = let title = d ^. ovalTitle
                         in  case cve ^? ix title of
                                 Just (nd, ns) -> d & ovalSeverity .~ ns & ovalRelease .~ nd
                                 Nothing -> d & ovalRelease .~ defaultDay title
        addTime d | d ^. ovalRelease == epoch = findCveInRef d
        addTime d = d

-- | From the base of the "serialized" directory, load all know ovals and
-- return the dispatch function.
ovalOnce
  :: FilePath
  -> IO (UnixVersion -> Maybe (Once ([OvalDefinition], HM.HashMap OTestId OFullTest)))
ovalOnce serdir = do
  let ld f = mkOnce . loadOvalSerialized $ serdir ++ "/" ++ f
  rhoval     <- ld "com.redhat.rhsa-all.xml"
  s11oval    <- ld "suse.linux.enterprise.server.11.xml"
  os122oval  <- ld "opensuse.12.2.xml"
  os123oval  <- ld "opensuse.12.3.xml"
  os132oval  <- ld "opensuse.13.2.xml"
  ubuntu1404 <- ld "com.ubuntu.trusty.cve.oval.xml"
  ubuntu1604 <- ld "com.ubuntu.xenial.cve.oval.xml"
  ubuntu1804 <- ld "com.ubuntu.bionic.cve.oval.xml"
  deb7       <- ld "oval-definitions-wheezy.xml"
  deb8       <- ld "oval-definitions-jessie.xml"
  deb9       <- ld "oval-definitions-stretch.xml"
  deb10      <- ld "oval-definitions-buster.xml"
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
  return ov

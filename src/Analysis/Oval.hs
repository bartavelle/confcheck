{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE TupleSections #-}
-- https://www.redhat.com/security/data/metrics/

module Analysis.Oval where

import Prelude
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.HashMap.Strict as HM
import qualified Data.Map.Strict as M
import qualified Data.Serialize as S
import Control.Lens
import Control.Monad
import Control.Applicative
import Data.Time.Calendar
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Text.Regex.PCRE.ByteString.Utils
import Data.List (intercalate)
import Data.Maybe (mapMaybe)
import Data.DebianVersion

import Data.Condition
import Data.Oval
import Analysis.Common
import Analysis.Types

epoch :: Day
epoch = fromGregorian 1970 1 1

getPackageinfo :: T.Text -> Maybe SoftwarePackage
getPackageinfo x = case reverse (T.splitOn "-" x) of
                       (v2 : v1 : vn) -> let v = v1 <> "-" <> v2
                                         in Just $ Package (T.intercalate "-" (reverse vn)) v PRPM
                       _ -> Nothing

defaultDay :: T.Text -> Day
defaultDay t = case preview (ix 1) (T.splitOn "-" t) >>= text2Int of
                   Just y -> fromGregorian (fromIntegral y) 1 1
                   Nothing -> epoch

loadOvalSerialized :: FilePath -> IO ([OvalDefinition], HM.HashMap OTestId OFullTest)
loadOvalSerialized f = do
    cnt <- BS.readFile f
    case S.decode cnt of
        Right (r, l) -> return (r, HM.fromList l)
        Left rr -> error ("loadOvalSerialized: " ++ rr)

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
        tolst Nothing = (False, [])
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
                          DpkgState sourcename rawversion | operation == LessThan -> do
                            v <- either (const Nothing) Just (parseDebianVersion rawversion)
                            (packagename, rv) <- M.lookup sourcename debs
                            guard (rv < v)
                            return [(packagename, Left v)]
                          Arch architectures | operation == PatternMatch -> do
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

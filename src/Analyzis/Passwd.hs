{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
module Analyzis.Passwd (analyzePasswdfile, analyzeUnixUsers) where

import Prelude
import qualified Data.Text as T
import qualified Data.Text.Read as T
import qualified Data.Set as S
import qualified Data.Map.Strict as M
import Data.Monoid
import Control.Applicative
import Control.Lens
import Control.Monad
import Data.Condition
import Data.Sequence (Seq)
import Data.Sequence.Lens
import qualified Data.Sequence as Seq
import qualified Data.Foldable as F

import Analyzis.Common
import Analyzis.Types
import Analyzis.Sudoers

import Data.Common (regroupMap)

r :: T.Text -> Int
r x = case T.decimal x of
          Right (n, "") -> n
          _ -> error ("Analyzis.Passwd: could not parse int: " <> show x)

parseValidShells :: T.Text -> [ConfigInfo]
parseValidShells = pure . ValidShells . S.fromList . filter (not . T.isPrefixOf "#") . map T.strip . T.lines

parsePwdEntry :: T.Text -> [ConfigInfo]
parsePwdEntry = map parseLine . T.lines
    where
        parseLine l =
            case T.splitOn ":" l of
                [u,p,uid,gid,gecos,home,shell] -> case ( (,) <$> T.decimal uid <*> T.decimal gid) of
                                                      Right ((uid',""), (gid',"")) -> ConfPass $ PasswdEntry u p uid' gid' gecos home shell
                                                      _ -> ConfigError $ MiscError ("Could not parse passwd line: " <> l)
                _ -> ConfigError $ MiscError ("Could not parse passwd line: " <> l)

parseGroupEntry :: T.Text -> [ConfigInfo]
parseGroupEntry = map parseLine . T.lines
    where
        parseLine l =
            case T.splitOn ":" l of
                [g,_,gid,members] -> ConfGroup $ GroupEntry g (r gid) (S.fromList (T.splitOn "," members))
                _ -> ConfigError $ MiscError ("Could not parse group line: " <> l)

parseShadowEntry :: T.Text -> [ConfigInfo]
parseShadowEntry = map parseLine . T.lines
    where
        geth ""   = SNoPassword
        geth "!"  = SLocked
        geth "LK" = SLocked
        geth "*"  = SLocked
        geth "!!" = SNotSetup
        geth x    = SHash x
        mr "" = Nothing
        mr x = Just (r x)
        parseLine l =
            case T.splitOn ":" l of
                (u:h:a:b:c:d:e:f:_) -> ConfShadow $ ShadowEntry u (geth h) (mr a) (mr b) (mr c) (mr d) (mr e) (mr f)
                _ -> ConfigError $ MiscError ("Could not parse shadow line: " <> l)

analyzePasswdfile :: [Analyzer (Seq ConfigInfo)]
analyzePasswdfile = [ Seq.fromList . parsePwdEntry     <$> requireTxtS "etc/passwd"
                    , Seq.fromList . parseShadowEntry  <$> requireTxtS "etc/shadow"
                    , Seq.fromList . parseGroupEntry   <$> requireTxtS "etc/group"
                    , Seq.fromList . parseValidShells  <$> requireTxtS "etc/shells"
                    ]
    where
        requireTxtS t = requireTxt ["conf/etc.tar.gz", t] <|> requireTxt ["conf/etc.tar.gz", T.cons '/' t]

analyzeUnixUsers :: Seq Vulnerability -> Seq Vulnerability
analyzeUnixUsers vulns = analyzeUnixUsers' pwd sha grp sud rh
    where
        g :: Prism' ConfigInfo a -> Seq a
        g prms = seqOf (folded . _ConfigInformation . prms) vulns
        pwd = g _ConfPass
        sha = g _ConfShadow
        grp = g _ConfGroup
        sud = g _CSudo
        rh  = toListOf (folded . _ConfigInformation . _CRhost ) vulns

analyzeUnixUsers' :: Seq PasswdEntry -> Seq ShadowEntry -> Seq GroupEntry -> Seq (Condition Sudo) -> [Rhost] -> Seq Vulnerability
analyzeUnixUsers' pwds shas grps sud rh = checkMultiple shas shadowUsername (MultipleShadow "username")
                                       <> checkMultiple grps groupName      (MultipleGroup  "groupname")
                                       <> checkMultiple grps groupGid       (MultipleGroup  "gid")
                                       <> checkMultiple pwds pwdUsername    (MultipleUser   "username")
                                       <> checkMultiple pwds pwdUid         (MultipleUser   "uid")
                                       <> Seq.fromList (map (Vulnerability High . VRhost) (filter (has (rhostSrc . _Nothing)) rh))
                                       <> F.foldMap analyzeUser unixusers
    where
        groupmap = M.fromList $ map (\g -> (g ^. groupGid, g)) $ F.toList grps
        shadowmap = M.fromList $ map (\s -> (s ^. shadowUsername, s)) $ F.toList shas
        membermap = M.fromListWith (++) [ (member, [g]) | g <- F.toList grps, member <- g ^.. groupMembers . folded ]
        rhostmap = M.fromListWith (++) (rh ^.. folded . to rhu . folded)
        rhu (Rhost Nothing _) = Nothing
        rhu x@(Rhost (Just u) _) = Just (u, [x])
        checkMultiple :: (Ord b, Eq b) => Seq a -> Lens' a b -> ([a] -> VulnType) -> Seq Vulnerability
        checkMultiple lst l mkvuln = fmap (Vulnerability Medium . mkvuln) (Seq.fromList $ M.elems mulmap)
            where
                emap = M.fromListWith (++) $ map (\x -> (x ^. l, [x])) $ F.toList lst
                mulmap = M.filter (\e -> length e > 1) emap
        unixusers = fmap mkunixuser pwds
            where
                mkunixuser u = let username = u ^. pwdUsername
                                   rhosts = regroupRHosts (rhostmap ^.. ix username . folded)
                               in  UnixUser u
                                    (shadowmap ^? ix username)
                                    (groupmap ^? ix (u ^. pwdGid))
                                    (membermap ^. ix username)
                                    mempty
                                    rhosts
        rootusers = Seq.filter (\u -> u ^. uupwd . pwdUid == 0) unixusers
        analyzeUser u = ConfigInformation (ConfUnixUser withsudo) Seq.<| vulns
            where
                withsudo = u & uusudo .~ (matchingSudos & traverse . _1 %~ view (uupwd . pwdUsername)
                                                        & traverse . _2 %~ (:[]) . extractCommands
                                                        & F.toList
                                                        & M.fromListWith (<>)
                                                        & fmap (simplifyCond1 . Or)
                                         )
                matchingSudos = do
                    root <- rootusers
                    guard (u /= root)
                    sudo <- sud
                    if isUserMatching u root sudo
                        then return (root, sudo)
                        else do
                            runas <- unixusers
                            guard (runas /= u)
                            guard (isUserMatching u runas sudo)
                            return (runas, sudo)

                vulns = mempty

regroupRHosts :: [Rhost] -> [Rhost]
regroupRHosts = map (\(k,v) -> Rhost k v) . M.toList . fmap simp . regroupMap (view rhostSrc) (view rhostCond)
    where
        simp :: [Condition RHCond] -> Condition RHCond
        simp [x] = x
        simp xs = simplifyCond1 (Or xs)

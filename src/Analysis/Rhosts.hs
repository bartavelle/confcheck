{-# LANGUAGE TupleSections #-}
module Analysis.Rhosts (anaRhosts) where

import Analysis.Types
import Analysis.Common
import Data.Condition

import Control.Applicative
import qualified Data.Text as T
import Data.Text (Text)
import Data.Sequence (Seq)
import Data.Monoid

data RhostSource = RSEquiv | RSUser Text
                 deriving (Show, Eq)

data RhostIdentifier = RHAny | RHNetgroup Text | RHId Text
                     deriving (Show, Eq)

data RhostEncoding = RhostEncoding RhostSource (Negatable RhostIdentifier) (Negatable RhostIdentifier)
                   deriving (Show, Eq)

anaRhosts :: Analyzer (Seq ConfigInfo)
anaRhosts = (uncurry anar <$> filterTxt isRHost) <|> (anaeq <$> (requireTxt ["conf/etc.tar.gz","/etc/hosts.equiv"] <|> requireTxt ["conf/etc.tar.gz", "etc/hosts.equiv"]))
    where
        isRHost [a,b] = (b == ".rhosts" || b == "/.rhosts") && "conf_user/" `T.isPrefixOf` a && "-conf.tar" `T.isSuffixOf` a
        isRHost _ = False

anar :: [Text] -> Text -> Seq ConfigInfo
anar [filename, ".rhosts"] cnt = anaRhost ("~" <> username <> "/.rhosts") (RSUser username) cnt
    where
        username = case T.stripPrefix "conf_user/" filename >>= T.stripSuffix "-conf.tar" of
                       Just n -> n
                       Nothing -> filename -- this is impossible too
anar _ _ = mempty -- impossible, given the previous conditions

anaeq :: Text -> Seq ConfigInfo
anaeq = anaRhost "/etc/hosts.equiv" RSEquiv

toRhost :: RhostEncoding -> Rhost
toRhost (RhostEncoding src host user) = Rhost muser conds
    where
        conds :: Condition RHCond
        conds = simplifyCond1 $ collapseCondition (And (map negatableToCondition [hostcond, usercond]))
        hostcond :: Negatable (Condition RHCond)
        hostcond = fmap (mkcond RHHost RHHostGroup) host
        usercond = fmap (mkcond RHUser RHUserGroup) user
        mkcond :: (Text -> RHCond) -> (Text -> RHCond) -> RhostIdentifier -> Condition RHCond
        mkcond single _ (RHId u) = Pure (single u)
        mkcond _ group (RHNetgroup u) = Pure (group u)
        mkcond _ _ RHAny = Always True
        muser = case src of
                    RSUser x -> Just x
                    _ -> Nothing

anaRhost :: Text -> RhostSource -> Text -> Seq ConfigInfo
anaRhost loc src = parseToConfigInfo loc (CRhost . toRhost . uncurry (RhostEncoding src)) . map rhostline . filter (\x -> not ("#" `T.isPrefixOf` x || T.null x)) . map T.strip . T.lines

rhostline :: Text -> Either String (Negatable RhostIdentifier, Negatable RhostIdentifier)
rhostline cnt = case T.words cnt of
                    [a,b] -> (,) <$> parseid a <*> parseid b
                    [a] -> (,Positive RHAny) <$> parseid a
                    _ -> Left ("Bad rhost line: " <> show cnt)

parseid :: Text -> Either String (Negatable RhostIdentifier)
parseid c | T.null c = Left "Empty rhost identifier"
          | T.head c == '-' = Negative <$> parseid' (T.tail c)
          | c == "+" = Right (Positive RHAny)
          | T.head c == '+' = Positive <$> parseid' (T.tail c)
          | otherwise = Positive <$> parseid' c
    where
        parseid' x | T.null x = Left "Empty rhost identifier, or lonely -"
                   | T.head x == '@' = Right (RHNetgroup (T.tail x))
                   | otherwise = Right (RHId x)
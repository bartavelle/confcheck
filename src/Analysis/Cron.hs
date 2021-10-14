{-# LANGUAGE OverloadedStrings #-}

module Analysis.Cron
  ( anaCrontab,
    anaUsercrontab,
  )
where

import Analysis.Common
import Analysis.Parsers
import Analysis.Shell
import Analysis.Types.ConfigInfo
import Analysis.Types.Cron
import Data.Char (isSpace)
import Data.Sequence (Seq)
import Data.Text (Text)
import qualified Data.Text as T
import Text.Megaparsec
import Text.Megaparsec.Char

anaCrontab :: Analyzer (Seq ConfigInfo)
anaCrontab =
  (uncurry tci <$> filterTxt iscrond)
    <|> (tci ["", "/etc/crontab"] <$> requireTxt ["conf/etc.tar.gz", "etc/crontab"])
  where
    tci x t =
      let lns = T.lines t
       in parseToConfigInfoMT CCronEntry lns (parseCrontab x lns)
    iscrond ["conf/etc.tar.gz", x] = "/etc/cron.d/" `T.isPrefixOf` x || "etc/cron.d/" `T.isPrefixOf` x
    iscrond _ = False

anaUsercrontab :: Analyzer (Seq ConfigInfo)
anaUsercrontab = tci <$> filterTxt isCrontab
  where
    tci (x, t) =
      let lns = T.lines t
       in parseToConfigInfoMT CCronEntry lns (parseUserCrontab x lns)
    isCrontab [x] = "crontab/" `T.isPrefixOf` x
    isCrontab _ = False

isSchedule :: Text -> Bool
isSchedule = isSchedule' . T.stripStart
  where
    isComment = (== '#') . T.head
    isEnv x =
      let (a, b) = T.break (== '=') x
       in not (T.null a) && T.all (`elem` ('_' : ['A' .. 'Z'] ++ ['0' .. '9'])) a
            && not (T.null b)
    isSchedule' t
      | T.null t = False
      | isComment t = False
      | isEnv t = False
      | "no crontab for" `T.isPrefixOf` t = False
      | "crontab: " `T.isPrefixOf` t = False
      | otherwise = True

parseCrontab :: [Text] -> [Text] -> [Either (ParseErrorBundle Text Void) CronEntry]
parseCrontab [_, src] = map (parse crontabparser (T.unpack src)) . filter isSchedule
parseCrontab _ = const []

parseSchedule :: Parser CronSchedule
parseSchedule = do
  lx (return ())
  at <- optional (char '@')
  let e = T.pack <$> lx (some (satisfy (not . isSpace)))
  lx $ case at of
    Just _ ->
      try (CronReboot <$ string "reboot")
        <|> try (CronYearly <$ string "yearly")
        <|> try (CronYearly <$ string "annually")
        <|> try (CronMonthly <$ string "monthly")
        <|> try (CronWeekly <$ string "weekly")
        <|> try (CronDaily <$ string "daily")
        <|> try (CronHourly <$ string "hourly")
    Nothing -> CronSchedule <$> e <*> e <*> e <*> e <*> e

parseCommand :: Text -> Parser (Text, [FilePath])
parseCommand u = do
  c <- some anySingle
  let tu = T.unpack u
  case toCommands ("Crontab of user " ++ tu) c of
    Right se -> return (T.pack c, se)
    Left rr -> fail rr

crontabparser :: Parser CronEntry
crontabparser = do
  s <- lx parseSchedule
  u <- lx parseUnixUser
  (c, ec) <- lx (parseCommand u)
  return (CronEntry u s c ec)

parseUserCrontab :: [Text] -> [Text] -> [Either (ParseErrorBundle Text Void) CronEntry]
parseUserCrontab [crontabname] = map (parse (ucrontabparser username) (T.unpack crontabname)) . filter isSchedule
  where
    username =
      fst $ T.breakOn "-"
        $ T.drop 1
        $ snd
        $ T.breakOn
          "/"
          crontabname
parseUserCrontab _ = const []

ucrontabparser :: Text -> Parser CronEntry
ucrontabparser u = do
  s <- lx parseSchedule
  (c, ec) <- lx (parseCommand u)
  return (CronEntry u s c ec)

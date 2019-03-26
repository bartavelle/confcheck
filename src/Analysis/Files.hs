{-# LANGUAGE TupleSections #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE BangPatterns #-}
module Analysis.Files (anaFilesNG, anaFilesOld, analyzeFS, normalFilepath, lineOld, lineNG', nhe, getParent, parseOldPerms) where

import qualified Data.Foldable as F
import Control.Lens
import Control.Monad
import System.FilePath
import Data.List
import qualified Data.HashMap.Strict as HM
import qualified Data.Map.Strict as M
import Data.Either
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString as BSB
import Control.Dependency
import qualified Data.Maybe.Strict as S
import qualified Data.Text.Encoding as T
import qualified Data.Thyme as Y
import qualified Data.Thyme.Time.Core as Y
import Control.Parallel.Strategies
import qualified Data.CompactMap as CM
import Data.Sequence.Lens
import Data.Text (Text)
import Data.Sequence (Seq)
import Data.Word (Word8)

import ByteString.Parser.Fast
import qualified ByteString.Parser.Fast as F
import Analysis.Types
import Analysis.Common
import Analysis.Sudoers
import Analysis.Files.Conditions
import Data.Condition
import Data.Parsers.Atto (englishMonthToInt)

isDigitFast :: Word8 -> Bool
isDigitFast x = x >= 0x30 && x <= 0x39

char2ft :: Char -> Maybe FileType
char2ft x = case x of
                '-' -> Just TFile
                'f' -> Just TFile
                'y' -> Just TFile
                'd' -> Just TDirectory
                'l' -> Just TLink
                'p' -> Just TPipe
                's' -> Just TSocket
                'b' -> Just TBlock
                'c' -> Just TChar
                'D' -> Just TDoor
                _ -> Nothing

parseTimestamp :: BS.ByteString -> Either F.ParseError Y.UTCTime
parseTimestamp txt | "%++" `BS.isPrefixOf` txt = Right $ Y.mkUTCTime (Y.fromGregorian 2016 03 12) (Y.fromSeconds (0 :: Int))
                   | otherwise = F.parseOnly F.timestamp txt

parseOnlyString :: Parser a -> BSB.ByteString -> Either String a
parseOnlyString parser input = parseOnly parser input
                             & _Left %~ show

lineNG' :: BS.ByteString -> Either String UnixFileParse
lineNG' t = case BS.words t of
                inode : hardlinks : dt1 : dt2 : dt3 : u : g : blocks : ft : prms : sz : rst -> do
                    let (path, target) = case break (== "->") rst of
                                             (a, []) -> (BS.unwords a, Nothing)
                                             (a, ["->"]) -> (BS.unwords a, Nothing)
                                             (a, b) -> (BS.unwords a, Just (BS.unwords (tail b)))
                        parseTS x = either (\rr -> Left ("Can't parse date: " ++ show x ++ ": " ++ show rr)) Right $ parseTimestamp x
                    !dt1' <- parseTS dt1
                    !dt2' <- parseTS dt2
                    !dt3' <- parseTS dt3
                    !ft''  <- getfiletype ft
                    !prm' <- parseOnlyString F.onum prms
                    let ft' = case (ft'', target) of
                                  (TFile, Just _) -> TLink
                                  _ -> ft''
                    return $! UnixFileGen (getInt inode)
                                          (getInt hardlinks)
                                          dt1'
                                          dt2'
                                          dt3'
                                          u
                                          g
                                          (getInt blocks)
                                          ft'
                                          prm'
                                          (getInt sz)
                                          path
                                          target
                _ -> Left ("Can't parse " <> show t)

parseOldPerms :: Parser FPerms
parseOldPerms = do
    let parseOldPerm :: Parser (Bool, Int)
        parseOldPerm = do
          rwx <- replicateM 3 (F.satisfy (`elem` ("rwxstST-" :: String)))
          case rwx of
            [r,w,x] ->
              let (s,ox) = case x of
                               '-' -> (False, False)
                               'x' -> (False, True)
                               'S' -> (True, False)
                               'T' -> (True, False)
                               _   -> (True, True)
              in  return (s, p 4 (r /= '-') + p 2 (w /= '-') + p 1 ox)
            _ -> error "can't happen in parseOldPerms"
        p x c = if c then x else 0
    (!suid, !u) <- parseOldPerm
    (!guid, !g) <- parseOldPerm
    (!stik, !o) <- parseOldPerm
    let !spec = p 4 suid + p 2 guid + p 1 stik
    return $! FPerms $! spec*8*8*8 + u*8*8 + g*8 + o

getint :: Integral n => BS.ByteString -> Either String n
getint t = BSB.foldl' parseDecimal (Right 0) t
    where
        parseDecimal (Left x) _ = Left x
        parseDecimal (Right c) d | isDigitFast d = Right (fromIntegral (d - 0x30) + c * 10)
                                 | otherwise = Left ("Could not read decimal " <> show t)

getfiletype :: BS.ByteString-> Either String FileType
getfiletype y | BS.null y = Left "Empty file type !?!"
              | otherwise = case char2ft (BS.head y) of
                                Just x -> Right x
                                Nothing -> Left ("Invalid file type " <> show y)

-- | Un parser "à la main", pourri à lire, mais 3x plus rapide que le
-- précédent ..
lineOld :: BS.ByteString -> Either String UnixFileParse
lineOld t = case BS.words t of
                 tinod : tblock : tperms : thard : tuser : tgroup : siz : rst ->
                     let (sz, dt, ptt) = case (BSB.all isDigitFast siz, BS.take 1 (BS.reverse siz), rst) of
                                                        (True , _  ,     a : b : c : d) -> (getint siz , pd a b c, d) -- normal case
                                                        (False, ",", _ : a : b : c : d) -> (pure 0, pd a b c, d) -- block device with 4,   5
                                                        (False, _  ,     a : b : c : d) -> (pure 0, pd a b c, d) -- block device with 4,5
                                                        _ -> (Left "couldn't parse size", Left "couldn't parse size", [])

                         pd m d hy = mkdate <$> getmonth m <*> getint d <*> getHourOrYear hy
                         getmonth tx = case englishMonthToInt tx of
                                          Just x -> Right x
                                          Nothing -> Left "Could not parse month"
                         getHourOrYear tx = case BS.split ':' tx of
                                               [h,m] -> (,,) <$> getint h <*> getint m <*> pure 2014 -- TODO make this year dynamic
                                               [y] -> (0,0,) <$> getint y
                                               _ -> Left "Too many : in year field"
                         mkdate mo d (h,mi,y) = Y.UTCTime (Y.YearMonthDay y mo d ^. from Y.gregorian) (Y.fromSeconds (h * 3600 + mi * 60 :: Int)) ^. from Y.utcTime
                         (pt, tgt) = case break (=="->") ptt of
                                         (a,b)  -> (Right (BS.unwords a),) $ if null b
                                                                                then Nothing
                                                                                else Just (BS.unwords (tail b))
                    in   UnixFileGen <$> getint tinod <*> getint thard <*> dt <*> dt <*> dt <*> pure tuser <*> pure tgroup <*> getint tblock <*> getfiletype (BS.take 1 tperms) <*> parseOnlyString parseOldPerms (BS.drop 1 tperms) <*> sz <*> pt <*> pure tgt
                 x -> Left ("bad number of blocks! : " <> show t <> " " <> show (length x))

anaFilesNG :: Analyzer (Seq ConfigInfo)
anaFilesNG = pure . ConfUnixFileNG <$> require ["fs/find-ng.txt"]

anaFilesOld :: Analyzer (Seq ConfigInfo)
anaFilesOld = pure . ConfUnixFile <$> require ["fs/find.txt"]

normalFilepath :: FP -> FP
normalFilepath = BS.pack . System.FilePath.joinPath . reverse . filterpp 0 . reverse . splitPath . BS.unpack
    where
        filterpp :: Int -> [FilePath] -> [FilePath]
        filterpp _ [] = []
        filterpp n ("../" : xs) = filterpp (n + 1) xs
        filterpp 0 (x : xs) = x : filterpp 0 xs
        filterpp n (_ : xs) = filterpp (n - 1) xs

parchunk :: [a] -> [a]
parchunk = withStrategy (parListChunk 200 rseq)

nhe :: Either a b -> Either a b
nhe x@(Left !_) = x
nhe x@(Right !_) = x

-- | Filtrer les commandes non spécifiées
sudoAll :: Condition Sudo -> Bool
sudoAll = not . F.any (\s -> trivial s || _sudoPasswd s == SudoTargetPassword)
    where
        trivial s = simplifyCond1 (_sudoCommand s) == Always True

analyzeFS :: M.Map VulnGroup (Seq Vulnerability) -> Seq Vulnerability -> Seq Vulnerability
analyzeFS vm allvulns =  fmap ConfigInformation (seqOf folded errors1 <> seqOf folded errors2)
                      <> fileCondition allconds filemap
    where
        allconds =  compileRules (  defFileRules <> map (_2 %~ uncurry cronRule) cronstuff <> map ((Medium,) . userFiles) userhomes )
                 <> [ CheckCondition (extractFileCondition sudoroot) sudocond sudocond (mkvsudo High)   (mkvpsudo High)
                    , CheckCondition (extractFileCondition sudouser) sudocond sudocond (mkvsudo Medium) (mkvpsudo Medium)
                    ]
        sudocond = Pure (\f -> worldWritable f || not (ownedBy "root" f))
        mkvsudo sev f = Vulnerability sev $ VFile $ if not (ownedBy "root" f)
                                                        then ShouldBeOwnedBy "root" "sudo root" f
                                                        else ShouldNotBeWritable "sudo root" f
        mkvpsudo sev c f = Vulnerability sev $ VFile $ if not (ownedBy "root" f)
                                                           then ShouldBeOwnedBy "root" (tfp c <> " can be run as root with sudo") f
                                                           else ShouldNotBeWritable (tfp c <> " can be run as root with sudo") f
        userlist = vm ^.. ix GAuthUnix . folded . _ConfigInformation . _ConfPass
        userhomes = map (T.encodeUtf8 . view pwdHome) userlist
        usermap  = HM.fromList $ map (mkpair pwdUid pwdUsername) userlist
        groupmap = HM.fromList (vm ^.. ix GAuthUnix . folded . _ConfigInformation . _ConfGroup . to (mkpair groupGid groupName))
        mkpair a b c = (c ^. a . to (BS.pack . show), c ^. b . to T.encodeUtf8)
        sudo = vm ^.. ix GAuthUnix . folded . _ConfigInformation . _CSudo . filtered sudoAll

        prepareCron :: (Text, FP) -> (Severity, (BS.ByteString, FP))
        prepareCron (u, p) = (if u == "root" then High else Medium, (T.encodeUtf8 u, p))
        cronstuff = nub (vm ^.. ix GCron . folded . _ConfigInformation . _CCronEntry . to extractCronFP . folded . to prepareCron)
        extractCronFP :: CronEntry -> [(Text, FP)]
        extractCronFP cron = do
            fp <- _cronExtractedCommands cron
            guard (isAbsolute fp)
            return (_cronUser cron, BS.pack fp)
        sudoroot, sudouser :: [Condition Sudo]
        (sudoroot, sudouser) = partition (checkCondition (checkUserCondition (dummyUser "root") . _sudoRunas))
                          $ filter (not . checkCondition (checkUserCondition (dummyUser "root") . _sudoUser)) sudo
        extractFileCondition :: [Condition Sudo] -> Condition (Pattern FP)
        extractFileCondition = simplifyCond1 . Or . map (fmap extractFC . extractCommands)
            where
                extractFC :: SudoCommand -> Pattern FP
                extractFC Visudo            = E "WRONG WRONG"
                extractFC (SudoDirectory d) = P (T.encodeUtf8 d)
                extractFC (SudoNoArgs c)    = E (T.encodeUtf8 c)
                extractFC (SudoAnyArgs c)   = E (T.encodeUtf8 c)
                extractFC (SudoArgs c _)    = E (T.encodeUtf8 c)

        (errors1, allunixfiles)   = parseUFWith lineOld _ConfUnixFile  "find.txt"
        (errors2, allunixfilesNG) = parseUFWith lineNG' _ConfUnixFileNG "find-ng.txt"
        parseUFWith :: (BS.ByteString -> Either String UnixFileParse) -> Prism' ConfigInfo BS.ByteString -> Text -> ([ConfigInfo], [UnixFileParse])
        parseUFWith prs prsm loc = prse (allvulns ^. folded . _ConfigInformation . prsm)
            where
                prse = part . partitionEithers . parchunk . fmap (nhe . prs) . BS.lines
                part = _1 . traverse %~ (\x -> ConfigError $ ParsingError loc x Nothing)
        filemap = fixUsersandLinks usermap groupmap allfiles
        allfiles = case (null allunixfiles, null allunixfilesNG) of
                      (True,_) -> allunixfilesNG
                      (_,True) -> allunixfiles
                      _        -> allunixfiles <> allunixfilesNG

fixUsersandLinks :: HM.HashMap BS.ByteString BS.ByteString
                 -> HM.HashMap BS.ByteString BS.ByteString
                 -> [UnixFileParse] -> CM.CompactMap FP UnixFileParse
fixUsersandLinks usermap groupmap = flip CM.fromList (view filePath) . parchunk . map (fixlinks . fixusers)
    where
        fixusers = (fileUser  %~ extractNameFrom usermap)
                 . (fileGroup %~ extractNameFrom groupmap)
        extractNameFrom mp x = HM.lookupDefault x x mp
        fixlinks f = f & fileTarget . _Just %~ normalFilepath . completeLink (f ^. filePath)

completeLink :: FP -> FP -> FP
completeLink cwd lnk | BS.null lnk = cwd
                     | BS.head lnk == '/' = lnk
                     | otherwise = case getParent cwd of
                                      S.Just p -> p <> "/" <> lnk
                                      S.Nothing -> "/" <> lnk


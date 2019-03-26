{-# LANGUAGE TemplateHaskell #-}
module Analysis.Sudoers (anasudo, isUserMatching, testCommand, extractCommands, commandMatch, checkUserCondition, parseCnt, extractSudoconfig, distributeEither) where


import qualified Data.List.NonEmpty as NE
import qualified Data.Text as T
import qualified Data.Textual as Txt
import qualified Data.Set as S
import qualified Data.Map.Strict as M
import qualified Data.Foldable as F
import qualified Data.Sequence as Seq
import Data.Text (Text)
import Data.Sequence (Seq)
import Network.IP.Addr

import Analysis.Types
import Analysis.Parsers
import Analysis.Common
import Data.Condition

import Text.Parsec.Text
import Text.Parsec.Error
import Text.Parsec.Prim (parse)

import Text.Parser.Token
import Text.Parser.LookAhead
import Text.Parser.Char
import Text.Parser.Combinators

import Data.Char (isUpper,isSpace)
import Data.List (nub,groupBy)
import Data.Either (partitionEithers)
import Data.Maybe (mapMaybe)
import Control.Applicative
import Control.Lens
import Control.Monad hiding (forM, mapM, sequence)
import Data.Traversable

type SudoList a = NE.NonEmpty (Negatable a)

data SudoerLine = UserAlias   (NE.NonEmpty SUser)
                | RunasAlias  (NE.NonEmpty SRunas)
                | HostAlias   (NE.NonEmpty SHost)
                | CmndAlias   (NE.NonEmpty SCmnd)
                | UserSpec    (SudoList NUser) (NE.NonEmpty SUserSpec)
                | Include     Text
                | Defaults    Text
                deriving (Show, Eq)

data SUserSpec = SUserSPec (SudoList NHost) (NE.NonEmpty SCmndSpec)
               deriving (Show, Eq)

data SCmndSpec = SCmndSpec RunAsSpec (S.Set TagSpec) (Negatable NCmnd)
               deriving (Show, Eq)

data TagSpec = NOPASSWD | PASSWD | NOEXEC | EXEC | SETENV | NOSETENV | LOG_INPUT | NOLOG_INPUT | LOG_OUTPUT | NOLOG_OUTPUT
             deriving (Show, Eq, Ord)

data RunAsSpec = RunasSpec [Negatable NUser] [Negatable NUser]
               deriving (Show, Eq)

data SUser  = SUser Text (SudoList NUser)
            deriving (Show, Eq)
data SRunas = SRunas Text (SudoList NUser)
            deriving (Show, Eq)
data SHost  = SHost Text (SudoList NHost)
            deriving (Show, Eq)
data SCmnd  = SCmnd Text (SudoList NCmnd)
            deriving (Show, Eq)

data NUser = UserName      Text
           | Uid           Int
           | Group         Text
           | Gid           Int
           | NetGroup      Text
           | NonUnixGroup  Text
           | NonUnixGid    Text
           | UserAliasName Text
           deriving (Show, Eq)

data NHost = NNetwork4      Net4Addr
           | NNetwork6      Net6Addr
           | NIP            IP
           | NNetgroup      Text
           | NHostAliasName Text
           | NHostname      Text
           deriving (Show, Eq)

data NCmnd = NCommand       Cmnd
           | NDirectory     Text
           | NCmndAliasName Text
           | NSudoEdit
           deriving (Show, Eq)

data Cmnd = Cmnd Text (Maybe [Text])
          deriving (Show, Eq)

makePrisms ''SudoerLine
makePrisms ''SUser
makePrisms ''SRunas
makePrisms ''SHost
makePrisms ''SCmnd

partitionNegatable :: F.Foldable f => f (Negatable a) -> ([a],[a]) -- (False, True)
partitionNegatable = partitionEithers . map toeithers . F.toList
    where
        toeithers (Positive x) = Right x
        toeithers (Negative x) = Left x

sepNE :: Char -> Parser a -> Parser (NE.NonEmpty a)
sepNE sep prs = NE.fromList <$> (prs `sepBy1` symbolic sep)

parseAlias :: String -> Parser a -> Parser (NE.NonEmpty a)
parseAlias h p = lx (string h) *> sepNE ':' p

literal :: Parser Text
literal = try stringLiteral <|> parseUnixUser

cmdarg :: Parser Text
cmdarg = try stringLiteral <|> litstring
    where
        litstring = do
            c <- T.pack <$> some (satisfy (\x -> not (isSpace x) && x /= ',' && x /= '\\'))
            l <- optional (lookAhead anyChar)
            case l of
                Just '\\' -> do
                    void $ char '\\'
                    escaped <- anyChar
                    rst <- litstring
                    return (c <> T.singleton escaped <> rst)
                _ -> return c

name :: Parser Text
name = T.pack <$> lx name'
    where
        name' = (:) <$> upper <*> many (satisfy (\x -> isUpper x || x == '_'))

negatable :: Parser a -> Parser (Negatable a)
negatable p = do
    negs <- many (char '!')
    if even (length negs)
        then Positive <$> p
        else Negative <$> p

runaslist :: Parser (SudoList NUser)
runaslist = sepNE ',' (negatable useralias')
    where
        useralias' = try (string "%:#" *> (NonUnixGid   <$> literal))
                 <|> try (string "%:"  *> (NonUnixGroup <$> literal))
                 <|> try (char '+'     *> (NetGroup     <$> literal))
                 <|> try (string "%#"  *> (Gid          <$> parseInt))
                 <|> try (char '%'     *> (Group        <$> literal))
                 <|> try (char '#'     *> (Uid          <$> parseInt))
                 <|> try (UserAliasName                 <$> name)
                 <|>     (UserName                      <$> literal)
                 <?> "user/runas alias"

useralias :: (Text -> SudoList NUser -> b) -> Parser b
useralias x = x <$> name <* symbolic '=' <*> runaslist

hostlist :: Parser (SudoList NHost)
hostlist = sepNE ',' (negatable (lx hostalias'))
    where
        hostalias' =   try (NNetwork4              <$> Txt.textual)
                   <|> try (NNetwork6              <$> Txt.textual)
                   <|> try (NIP                    <$> Txt.textual)
                   <|> try (char '+' *> (NNetgroup <$> literal))
                   <|> try (NHostAliasName         <$> name)
                   <|>     (NHostname              <$> literal)
                   <?> "host alias"


hostalias :: Parser SHost
hostalias = SHost <$> name <* symbolic '=' <*> hostlist

cmnd :: Parser NCmnd
cmnd = try (lx (string "sudoedit") *> pure NSudoEdit)
   <|> try (NCmndAliasName <$> name)
   <|> try (NDirectory     <$> directory)
   <|>     (NCommand       <$> cmd)
   <?> "command alias"
   where
        directory = commandname >>= \d -> if T.last d == '/'
                                         then return d
                                         else fail "Doesn't end with '/'"
        cmd = Cmnd <$> lx (commandname >>= checkFullyqualified) <*> commandargs
        commandname = T.pack <$> some (satisfy (\x -> x /= ',' && not (isSpace x))) <?> "command name"
        checkFullyqualified t | T.null t = fail "Empty command ? Shoud not happen."
                              | T.head t == '/' = return t
                              | otherwise = fail "Expected a fully qualified path"
        commandargs =   try (string "\"\"" *> pure (Just []))
                    <|> optional (some (lx cmdarg))
                    <?> "command argument"
cmndalias :: Parser SCmnd
cmndalias = SCmnd <$> name <* symbolic '=' <*> sepNE ',' (negatable cmnd)

useraliases :: Parser (NE.NonEmpty SUser)
useraliases = parseAlias "User_Alias" (useralias SUser)

runasaliases :: Parser (NE.NonEmpty SRunas)
runasaliases = parseAlias "Runas_Alias" (useralias SRunas)

hostaliases :: Parser (NE.NonEmpty SHost)
hostaliases = parseAlias "Host_Alias" hostalias

cmndaliases :: Parser (NE.NonEmpty SCmnd)
cmndaliases = parseAlias "Cmnd_Alias" cmndalias

userspec :: Parser SUserSpec
userspec = SUserSPec <$> hostlist <* symbolic '=' <*> sepNE ',' cmndspec

cmndspec :: Parser SCmndSpec
cmndspec = SCmndSpec <$> lx runasspec <*> (S.fromList <$> (tagspec `sepEndBy` symbolic ':')) <*> negatable cmnd

tagspec :: Parser TagSpec
tagspec =   try (string "NOPASSWD"     *> pure NOPASSWD)
        <|> try (string "PASSWD"       *> pure PASSWD)
        <|> try (string "NOEXEC"       *> pure NOEXEC)
        <|> try (string "EXEC"         *> pure EXEC)
        <|> try (string "SETENV"       *> pure SETENV)
        <|> try (string "NOSETENV"     *> pure NOSETENV)
        <|> try (string "LOG_INPUT"    *> pure LOG_INPUT)
        <|> try (string "NOLOG_INPUT"  *> pure NOLOG_INPUT)
        <|> try (string "LOG_OUTPUT"   *> pure LOG_OUTPUT)
        <|> try (string "NOLOG_OUTPUT" *> pure NOLOG_OUTPUT)
        <?> "tag spec"

runasspec :: Parser RunAsSpec
runasspec = do
    r <- optional $ parens $ do
       u <- optional runaslist
       g <- optional $ do
           void $ symbolic ':'
           optional runaslist
       return (u,g)
    pure $ RunasSpec (r ^.. _Just . _1 . _Just . folded) (r ^.. _Just . _2 . _Just . folded . folded)

sudoline :: Parser SudoerLine
sudoline =   try (UserAlias  <$> useraliases)
         <|> try (RunasAlias <$> runasaliases)
         <|> try (HostAlias  <$> hostaliases)
         <|> try (CmndAlias  <$> cmndaliases)
         <|> try (UserSpec   <$> lx runaslist <*> sepNE ':' userspec)
         <|> (lx (string "Defaults") *> (Defaults . T.pack <$> some (satisfy (/= '\n'))))

parseCnt :: Text -> [(Text, Either ParseError SudoerLine)]
parseCnt cnt = zip lns $ map (parse (sudoline <* comments) "dummy") lns
    where
        comments = eof <|> void (char '#')
        lns = filter hascontent $ map T.stripStart $ regrouplines $ T.lines cnt
        hascontent t | "#include" `T.isPrefixOf` t = False -- TODO
                     | "#" `T.isPrefixOf` t = False
                     | T.null t = False
                     | otherwise = True
        regrouplines (a : b : xs) | "\\" `T.isSuffixOf` a = regrouplines (T.init a <> b : xs)
                                  | otherwise = a : regrouplines (b : xs)
        regrouplines x = x

resolveUser :: F.Foldable f => M.Map Text (SudoList NUser) -> Text -> f (Negatable NUser) -> Either Text (Condition SudoUserId)
resolveUser usermap origline = resolveSudoList ru
    where
        ru nuser = case nuser of
                       UserName x      -> pure $ Pure $ SudoUsername x
                       Uid x           -> pure $ Pure $ SudoUid x
                       Group x         -> pure $ Pure $ SudoGroupname x
                       Gid x           -> pure $ Pure $ SudoGid x
                       UserAliasName "ALL" -> pure $ Always True
                       UserAliasName n -> case usermap ^? ix n of
                                              Nothing -> Left ("Unknown user alias " <> n <> " on line " <> origline)
                                              Just m -> resolveUser usermap origline m
                       x -> Left ("Can't decide condition " <> T.pack (show x) <> " on line " <> origline)

resolveHost :: M.Map Text (SudoList NHost) -> Text -> SudoList NHost -> Either Text (Condition SudoHostId)
resolveHost hostmap origline = resolveSudoList rh
    where
        rh nh = case nh of
                    NNetwork4 x -> pure $ Pure $ SudoNet4 x
                    NNetwork6 x -> pure $ Pure $ SudoNet6 x
                    NIP x       -> pure $ Pure $ SudoIP x
                    NHostname x -> pure $ Pure $ SudoHostname x
                    NNetgroup _ -> pure $ Always True -- TODO
                    NHostAliasName "ALL" -> pure $ Always True
                    NHostAliasName n -> case hostmap ^? ix n of
                                            Nothing -> Left ("Unknown host alias " <> n <> " on line " <> origline)
                                            Just m -> resolveHost hostmap origline m

-- TODO negation is ignored !
resolveCmndlist :: M.Map Text (SudoList NCmnd) -> Text -> NCmnd -> Either Text (Condition SudoCommand)
resolveCmndlist commandmap origline = resolveSudoList rescmnd . (:[]) . Positive
    where
        rescmnd :: NCmnd -> Either Text (Condition SudoCommand)
        rescmnd (NDirectory x)                = pure $ Pure $ SudoDirectory x
        rescmnd (NCommand (Cmnd x (Just []))) = pure $ Pure $ SudoNoArgs x
        rescmnd (NCommand (Cmnd x (Just xs))) = pure $ Pure $ SudoArgs x xs
        rescmnd (NCommand (Cmnd x Nothing))   = pure $ Pure $ SudoAnyArgs x
        rescmnd NSudoEdit                     = pure $ Pure Visudo
        rescmnd (NCmndAliasName "ALL")        = pure $ Always True
        rescmnd (NCmndAliasName n) = case commandmap ^? ix n of
                                         Nothing -> Left ("Unknown command alias " <> n <> " on line " <> origline)
                                         Just m -> resolveSudoList rescmnd m

resolveSudoList :: Eq b => F.Foldable f => (a -> Either Text (Condition b)) -> f (Negatable a) -> Either Text (Condition b)
resolveSudoList f = fmap (simplifyCond1 . tocond . partitionNegatable) . mapM resolvea . F.toList
    where
        resolvea  = sequence . fmap f

tocond :: ([Condition b], [Condition b]) -> Condition b
tocond ([], []) = Always True
tocond ([], pos) = Or pos
tocond (neg, []) = Not (Or neg)
tocond (neg,pos) = And [Not (Or neg), Or pos]

propagateDefaults :: ([Negatable NUser], [Negatable NUser]) -> [SCmndSpec] -> [SCmndSpec]
propagateDefaults _ [] = []
propagateDefaults (a, b) (SCmndSpec (RunasSpec [] []) tags ncmnd : xs) = SCmndSpec (RunasSpec a b) tags ncmnd : propagateDefaults (a,b) xs
propagateDefaults _ (s@(SCmndSpec (RunasSpec runasusers runasgroups) _ _) : xs) = s : propagateDefaults (runasusers, runasgroups) xs

resolveSpec :: Bool -- ^ target password
            -> M.Map Text (SudoList NUser)
            -> M.Map Text (SudoList NHost)
            -> M.Map Text (SudoList NUser)
            -> M.Map Text (SudoList NCmnd)
            -> SudoList NUser
            -> NE.NonEmpty SUserSpec
            -> Text
            -> Either Text (Condition Sudo)
resolveSpec tgtpass usermap hostmap runasmap cmndmap users specs origline = do
    usercond <- resolveUser usermap origline users
    fmap (simplifyCond1 . And) $ forM (F.toList specs) $ \(SUserSPec hosts commands) -> do
        hostcond <- resolveHost hostmap origline hosts
        cmdconds <- forM (propagateDefaults mempty $ F.toList commands) $ \(SCmndSpec (RunasSpec runasusers runasgroups) tags ncmnd) -> do
            runascondu <- resolveUser runasmap origline runasusers
            runascondg <- resolveUser runasmap origline runasgroups
            let runascond = simplifyCond1 $ And [runascondu, fmap togroup runascondg]
                togroup (SudoUsername x) = SudoGroupname x
                togroup (SudoUid x) = SudoGid x
                togroup x = x
            cmdlist <- traverse (resolveCmndlist cmndmap origline) ncmnd
            let rcmd y = case y of
                           Negative x -> Not x
                           Positive x -> x
                passSituation | NOPASSWD `S.member` tags = SudoNoPassword
                              | tgtpass = SudoTargetPassword
                              | otherwise = SudoMyPassword
            return $ Sudo usercond hostcond runascond passSituation (rcmd cmdlist) origline
        let groupedCmds = map regroup $ groupBy (\(Sudo u1 h1 r1 t1 _ ln1) (Sudo u2 h2 r2 t2 _ ln2) -> u1 == u2 && h1 == h2 && r1 == r2 && t1 == t2 && ln1 == ln2) $ filter ((/= SudoTargetPassword) . _sudoPasswd) cmdconds
            regroup [] = error "The impossible happened at resolveSpec"
            regroup lst@(Sudo u h r t _ ln:_) = Sudo u h r t (And (map _sudoCommand lst)) ln
        return $ Or (map Pure groupedCmds)

hasTargetpw :: [(Text, SudoerLine)] -> Bool
hasTargetpw = has (folded . _2 . _Defaults . filtered (T.isPrefixOf "targetpw"))

extractSudoconfig :: [(Text, SudoerLine)] -> [Either Text (Condition Sudo)]
extractSudoconfig lns = mapMaybe getUserSpec lns
    where
        usermap  = M.fromList (lns ^.. folded . _2 . _UserAlias  . folded . _SUser)
        hostmap  = M.fromList (lns ^.. folded . _2 . _HostAlias  . folded . _SHost)
        runasmap = M.fromList (lns ^.. folded . _2 . _RunasAlias . folded . _SRunas)
        cmndmap  = M.fromList (lns ^.. folded . _2 . _CmndAlias  . folded . _SCmnd)
        targetPassword = hasTargetpw lns
        getUserSpec (l, UserSpec a b) = Just (resolveSpec targetPassword usermap hostmap runasmap cmndmap a b l)
        getUserSpec _ = Nothing


checkUserCondition :: UnixUser -> Condition SudoUserId -> Bool
checkUserCondition uuser = checkCondition cu
    where
        username = uuser ^. uupwd  . pwdUsername
        userid = uuser ^. uupwd  . pwdUid
        groups = uuser ^.. uugrp . folded <> uuser ^. uuextra
        gids = groups ^.. folded . groupGid
        groupnames = groups ^.. folded . groupName
        cu (SudoUsername x) = x == username
        cu (SudoUid x) = x == userid
        cu (SudoGroupname x) = x `elem` groupnames
        cu (SudoGid x) = x `elem` gids

testCommand :: UnixUser -> UnixUser -> Text -> [Text] -> [Condition Sudo] -> Bool
testCommand uuser runas ucom uargs = any (checkCondition test')
    where
        test' (Sudo usercheck _ runascheck situation com _) = checkUserCondition uuser usercheck && checkUserCondition runas runascheck && checkCondition commandmatch com && situation /= SudoTargetPassword
        commandmatch com = case com of
                               Visudo -> null uargs && ucom == "visudo"
                               SudoDirectory d -> d `T.isPrefixOf` ucom
                               SudoNoArgs c    -> c == ucom && null uargs
                               SudoAnyArgs c   -> c == ucom
                               SudoArgs c a    -> c == ucom && a == uargs

-- TODO : fix les problèmes de matching negatifs
isUserMatching :: UnixUser  -- tested user
               -> UnixUser  -- "runas" user
               -> Condition Sudo -- the condition to test
               -> Bool
isUserMatching uuser ruser = checkCondition chk
    where
        chk (Sudo usercheck _ runascheck situation _ _) = checkUserCondition uuser usercheck && checkUserCondition ruser runascheck && situation /= SudoTargetPassword

commandMatch :: Text -> Condition SudoCommand -> Bool
commandMatch t = checkCondition chk
    where
        chk Visudo = False
        chk (SudoDirectory d) = d `T.isPrefixOf` t
        chk (SudoNoArgs f)    = f == t
        chk (SudoAnyArgs f)   = f == t
        chk (SudoArgs f _)    = f == t

extractCommands :: Condition Sudo -> Condition SudoCommand
extractCommands = Or . nub . map _sudoCommand . F.toList

distributeEither :: (a, Either b c) -> Either (a, b) (a, c)
distributeEither (a, Left b)  = Left (a, b)
distributeEither (a, Right b) = Right (a, b)

anasudo :: Analyzer (Seq ConfigInfo)
anasudo = gensudorules . snd <$> filterTxt isSudoers
    where
        isSudoers ["conf/etc.tar.gz", x] = "etc/sudoers" `T.isInfixOf` x
        isSudoers _  = False
        gensudorules cnt =
            let (parseErrors, goodParse) = parseCnt cnt & traverse %~ distributeEither
                                                        & partitionEithers
                -- TODO find a mathematical way to do the distribution
                errorsParse = Seq.fromList $ map (uncurry parseErrorToConfigInfo . (_1 %~ Just)) parseErrors
                (interpretationErrors, sudoconds) = partitionEithers (extractSudoconfig goodParse)
            in  errorsParse <> Seq.fromList (map (ConfigError . MiscError) interpretationErrors)
                            <> Seq.fromList (map CSudo sudoconds)
                            <> if hasTargetpw goodParse
                                   then Seq.singleton (ConfigError (MiscError "sudoers contains 'Defaults targetpw', it is probably not configured"))
                                   else mempty

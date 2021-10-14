{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Data.Oval
  ( parseOvalStream,
    parseOvalFile,
    OReference (..),
    OvalDefinition (..),
    OTestId (..),
    OFullTest (..),
    TestType (..),
    Operation (..),
    OvalStateOp (..),
    orRefid,
    orRefurl,
    orSource,
    ovalDesc,
    ovalReferences,
    ovalRelease,
    ovalSeverity,
    ovalTitle,
    ovalCond,
    ovalId,
    ovalLine,
  )
where

import Analysis.Types.Package
import Analysis.Types.Vulnerability
import Control.Applicative
import Control.Lens hiding (element, op)
import Control.Monad
import qualified Data.ByteString.Lazy as BSL
import Data.Condition
import qualified Data.HashMap.Strict as HM
import Data.Hashable
import Data.Maybe (catMaybes, fromMaybe)
import Data.Parsers.Xml
import Data.Serialize (Serialize (..))
import qualified Data.Text as T
import Data.Time.Calendar
import Debug.Trace
import GHC.Generics hiding (to)
import qualified Text.Parsec.Pos as P
import qualified Text.Parsec.Prim as P
import Text.Read (readMaybe)
import Prelude

newtype ObjectId = ObjectId T.Text
  deriving (Show, Eq, Hashable)

newtype StateId = StateId T.Text
  deriving (Show, Eq, Hashable)

newtype OTestId = OTestId T.Text
  deriving (Show, Eq, Hashable, Serialize)

data OReference
  = OReference
      { _orSource :: T.Text,
        _orRefid :: T.Text,
        _orRefurl :: T.Text
      }
  deriving (Show, Generic)

data Operator
  = CritAnd
  | CritOr
  deriving (Show)

data OvalDefinition
  = OvalDefinition
      { _ovalId :: T.Text,
        _ovalTitle :: T.Text,
        _ovalReferences :: [OReference],
        _ovalDesc :: T.Text,
        _ovalCond :: Condition OTestId,
        _ovalSeverity :: Severity,
        _ovalLine :: Int,
        _ovalRelease :: Day
      }
  deriving (Show, Generic)

instance Serialize OReference

instance Serialize Operation

instance Serialize TestType

instance Serialize OFullTest

instance Serialize OvalDefinition

instance Serialize OvalStateOp

data OvalTest
  = RpmInfoT !OTestId !ObjectId !(Maybe StateId)
  | FamilyT !OTestId !ObjectId !StateId
  | UnameT !OTestId !ObjectId !(Maybe StateId)
  | UnknownT
  | DpkgInfoT !OTestId !ObjectId !(Maybe StateId)
  | Unhandled !OTestId !ObjectId !StateId !TestDetails
  | TestAlways !OTestId !Bool !T.Text -- why always?
  | VersionIs !OTestId !T.Text
  | IVersionIs !OTestId ![Int]
  | MVersionIs !OTestId !Int
  deriving (Show)

data TestDetails
  = TestDetails
      { _tdName :: T.Text,
        _tdCheck :: T.Text,
        _tdCE :: T.Text,
        _tdComment :: T.Text
      }
  deriving (Show)

data OvalObject
  = RpmO !ObjectId !T.Text
  | FamilyO !ObjectId
  | UnameO !ObjectId
  | DpkgO !ObjectId !T.Text
  | ReleaseCodenameO !ObjectId
  | FileContent !ObjectId !T.Text !T.Text !T.Text
  deriving (Show)

data Operation
  = LessThan
  | Equal
  | PatternMatch
  | GreaterThanOrEqual
  deriving (Show, Generic, Eq)

data OvalState = OvalState !StateId !OvalStateOp
  deriving (Show)

data OvalStateOp
  = OvalStateOp !TestType !Operation
  | AndStateOp !OvalStateOp !OvalStateOp
  deriving (Show, Generic)

data TestType
  = RpmState !RPMVersion
  | DpkgState !(Maybe T.Text) !T.Text
  | Version !T.Text
  | IVersion ![Int]
  | SignatureKeyId !T.Text
  | FamilyIs !T.Text
  | UnameIs !T.Text
  | Exists
  | MiscTest !T.Text !T.Text
  | Arch !T.Text
  | TTBool !Bool !T.Text -- describe why this is always true
  deriving (Show, Generic, Eq)

data OFullTest
  = OFullTest
      { _ofulltestObject :: !T.Text,
        _ofulltestOp :: !OvalStateOp
      }
  deriving (Show, Generic)

makeLenses ''OReference

makeLenses ''OvalDefinition

criteria :: Parser (Condition OTestId)
criteria = lx (criterion <|> grp P.<?> "criteria")
  where
    criterion = Pure . OTestId <$> element "criterion" (extractParameter "test_ref") P.<?> "criterion"
    grp = element "criteria" getGroup P.<?> "grp"
    getGroup mp = (readOperator mp <*> some criteria) <|> (lx (some (ignoreElement "extend_definition")) *> criteria)
    readOperator mp = extractParameter "operator" mp >>= \x -> case x of
      "OR" -> pure Or
      "AND" -> pure And
      _ -> fail ("Unknown operator " <> T.unpack x)

translateCriticity :: T.Text -> Either String Severity
translateCriticity t =
  case t of
    "Untriaged" -> Right Unknown
    "" -> Right Unknown
    "Not set" -> Right Unknown
    "Negligible" -> Right None
    "None" -> Right None
    "Low" -> Right Low
    "Medium" -> Right Medium
    "Moderate" -> Right Medium
    "Critical" -> Right High
    "Important" -> Right High
    "High" -> Right High
    _ -> Left ("Unknown criticity " <> show t)

definition :: Parser (Maybe OvalDefinition)
definition = lx $ element "definition" $ \args ->
  case HM.lookup "class" args of
    Just "inventory" -> Nothing <$ (lx (ignoreElement "metadata") *> lx (ignoreElement "criteria"))
    _ -> do
      p <- P.getPosition
      defid <- extractParameter "id" args
      (title, refs, desc, msev) <- lx $ element_ "metadata" $ do
        title' <- lx $ getTextFrom "title"
        desc1 <- lx $ optional $ getTextFrom0 "description"
        lx $ ignoreElement "affected"
        refs' <-
          lx $
            many
              ( lx $
                  element
                    "reference"
                    ( \mp ->
                        OReference <$> extractParameter "source" mp
                          <*> extractParameter "ref_id" mp
                          <*> extractParameter "ref_url" mp
                    )
              )
        desc' <- maybe (lx $ getTextFrom0 "description") pure desc1
        lx $ void $ optional $ ignoreElement "debian" -- TODO, there is a better description in this
        msev' <- optional $ lx $ element_ "advisory" $ do
          cnt <- lx $ optional $ getTextFrom0 "severity"
          let ignoredElementsTags =
                [ "rights",
                  "cve",
                  "bugzilla",
                  "affected_cpe_list",
                  "bug",
                  "ref",
                  "assigned_to",
                  "public_date_at_usn",
                  "discovered_by",
                  "crd"
                ]
              ignoredElements = elementRPred (`elem` ignoredElementsTags) (const (ignoreNested [])) P.<?> "ignored metadata"
              parsedDate =
                elementRPred (`elem` ["issued", "updated"]) (extractParameter "date" >=> mkDate)
                  <|> lx (getTextFrom "public_date" >>= mkDate)
                  P.<?> "definition date"
              mkDate dt = case mapM (readMaybe . T.unpack . T.takeWhile (/= ' ')) (T.splitOn "-" dt) of
                Just [y, m, d] -> pure $ fromGregorian y (fromIntegral m) (fromIntegral d)
                _ -> fail ("Can't parse date " <> show dt)
          mdays <-
            many
              ( (Nothing <$ lx ignoredElements)
                  <|> (Just <$> lx parsedDate)
              )
          sev <- case cnt of
            Nothing -> pure Unknown
            Just txt -> either fail return (translateCriticity txt)
          return $ (sev,) $ case catMaybes mdays of
            (x : _) -> x
            _ -> fromGregorian 1970 1 1
        return (title', refs', desc', msev')
      P.skipMany $ ignoreElement "notes"
      crit <- criteria <|> pure (Always False)
      let (sev, res) = fromMaybe (Unknown, fromGregorian 1970 1 1) msev
      return $! Just $! OvalDefinition defid title refs desc crit sev (P.sourceLine p) res

object :: Parser OvalObject
object = lx (rpmObject <|> dpkgInfoObject <|> familyObject <|> unameObject <|> textFileContentObject <|> releaseCodenameObject)

dpkgInfoObject :: Parser OvalObject
dpkgInfoObject = element "dpkginfo_object" $ \mp -> do
  oid <- objectId mp
  nm <- lx $ element_ "name" $ do
    txt <- mconcat <$> many characterdata
    if T.null txt
      then do
        p <- P.getPosition
        comment <- optional (extractParameter "comment" mp)
        case comment >>= T.stripPrefix "The '" >>= T.stripSuffix "' package binaries." of
          Nothing ->
            "????"
              <$ traceM ("Warning, empty object name for oid " ++ show oid ++ " [" ++ show (comment, p) ++ "]")
          Just pname -> pure pname
      else pure txt
  pure (DpkgO oid nm)

textFileContentObject :: Parser OvalObject
textFileContentObject = element "textfilecontent54_object" $ \mp -> do
  filepath <-
    lx
      ( getTextFrom0 "filepath" <|> do
          pth <- lx $ getTextFrom0 "path"
          fname <- lx $ getTextFrom0 "filename"
          pure (pth <> "/" <> fname)
      )
  ptrn <- lx $ getTextFrom0 "pattern"
  inst <- lx $ getTextFrom0 "instance"
  oid <- objectId mp
  pure $ case (filepath, ptrn, inst) of
    ("/etc/debian_version", "(\\d+)\\.\\d", "1") -> ReleaseCodenameO oid
    ("/etc/lsb-release", _, "1") -> ReleaseCodenameO oid
    _ -> FileContent oid filepath ptrn inst

releaseCodenameObject :: Parser OvalObject
releaseCodenameObject = anyElement $ \ename mp -> do
  comment <- optional (extractParameter "comment" mp)
  oid <- objectId mp
  ignoreNested []
  case comment of
    Just "The singleton release codename object." -> return (ReleaseCodenameO oid)
    _ | ename == "red-def:rpmverifyfile_object" -> return (ReleaseCodenameO oid)
    _ -> fail ("Unknown object " ++ maybe "no comment" T.unpack comment ++ " in object " ++ T.unpack ename)

familyObject :: Parser OvalObject
familyObject = element "family_object" $ fmap UnameO . objectId

unameObject :: Parser OvalObject
unameObject = element "uname_object" $ fmap UnameO . objectId

rpmObject :: Parser OvalObject
rpmObject = element "rpminfo_object" $
  \mp ->
    RpmO <$> (ObjectId <$> extractParameter "id" mp)
      <*> lx (getTextFrom "name")

test :: Parser OvalTest
test = lx (rpmtest <|> dpkgInfoTest <|> familyTest <|> unameTest <|> unknownTest <|> unhandledTest)

withid :: (OTestId -> Parser a) -> HM.HashMap T.Text T.Text -> Parser a
withid a mp = extractParameter "id" mp >>= a . OTestId

objectId :: HM.HashMap T.Text T.Text -> Parser ObjectId
objectId = fmap ObjectId . extractParameter "id"

objectRef :: Parser ObjectId
objectRef = ObjectId <$> lx (element "object" (extractParameter "object_ref"))

stateRef :: Parser StateId
stateRef = StateId <$> lx (element "state" (extractParameter "state_ref"))

genTest :: T.Text -> (OTestId -> ObjectId -> StateId -> a) -> Parser a
genTest t c = element t $ withid $ \rid ->
  c rid <$> objectRef <*> stateRef

rpmtest :: Parser OvalTest
rpmtest = element "rpminfo_test" $ withid $ \rid ->
  RpmInfoT rid <$> objectRef <*> optional stateRef

unknownTest :: Parser OvalTest
unknownTest = UnknownT <$ ignoreElement "unknown_test"

automaticResults :: HM.HashMap T.Text (OTestId -> OvalTest)
automaticResults =
  HM.fromList
    [ ("Is the host running Ubuntu trusty?", (`IVersionIs` [14, 4])),
      ("Is the host running Ubuntu xenial?", (`IVersionIs` [16, 4])),
      ("Is the host running Ubuntu bionic?", (`IVersionIs` [18, 4])),
      ("Is the host running Ubuntu eoan?", (`IVersionIs` [19, 10])),
      ("Is the host running Ubuntu focal?", (`IVersionIs` [20, 4])),
      ("Debian GNU/Linux 11 is installed", (`MVersionIs` 11)),
      ("Debian GNU/Linux 10 is installed", (`MVersionIs` 10)),
      ("Debian GNU/Linux 9 is installed", (`MVersionIs` 9)),
      ("Debian GNU/Linux 8 is installed", (`MVersionIs` 8)),
      ("Debian GNU/Linux 7 is installed", (`MVersionIs` 7)),
      ("Red Hat CoreOS 4 is installed", (`MVersionIs` 4)),
      ("Red Hat Enterprise Linux 3 is installed", (`MVersionIs` 3)),
      ("Red Hat Enterprise Linux 4 is installed", (`MVersionIs` 4)),
      ("Red Hat Enterprise Linux 5 is installed", (`MVersionIs` 5)),
      ("Red Hat Enterprise Linux 6 is installed", (`MVersionIs` 6)),
      ("Red Hat Enterprise Linux 7 is installed", (`MVersionIs` 7)),
      ("Red Hat Enterprise Linux 8 is installed", (`MVersionIs` 8)),
      ("Red Hat Enterprise Linux must be installed", \rid -> TestAlways rid False "RHL trick")
    ]

unhandledTest :: Parser OvalTest
unhandledTest = anyElement $ \ename mp -> do
  rid <- OTestId <$> extractParameter "id" mp
  objid <- objectRef
  sttid <- stateRef
  mcomment <- fromMaybe "???" <$> optional (extractParameter "comment" mp)
  details <-
    TestDetails ename <$> extractParameter "check" mp
      <*> ( extractParameter "check_existence" mp
              <|> pure mcomment
          )
      <*> pure mcomment
  pure $ case HM.lookup (_tdComment details) automaticResults of
    Just r -> r rid
    Nothing
      | "kernel earlier than " `T.isPrefixOf` _tdComment details ->
        TestAlways rid False (_tdComment details) -- TODO true or false??
      | "kernel-rt earlier than " `T.isPrefixOf` _tdComment details ->
        TestAlways rid False (_tdComment details) -- TODO :/
      | otherwise -> Unhandled rid objid sttid details

familyTest :: Parser OvalTest
familyTest = genTest "family_test" FamilyT

unameTest :: Parser OvalTest
unameTest = element "uname_test" $ withid $ \rid ->
  UnameT rid <$> objectRef <*> optional stateRef

dpkgInfoTest :: Parser OvalTest
dpkgInfoTest = element "dpkginfo_test" $ withid $ \rid ->
  DpkgInfoT rid <$> objectRef <*> optional stateRef

extractOperation :: T.Text -> Parser Operation
extractOperation "less than" = pure LessThan
extractOperation "greater than or equal" = pure GreaterThanOrEqual
extractOperation "equals" = pure Equal
extractOperation "pattern match" = pure PatternMatch
extractOperation x = fail ("Unknown operator " <> T.unpack x)

state :: Parser OvalState
state = lx $ anyElement $ \ename mp -> do
  sid <- StateId <$> extractParameter "id" mp
  case snd (prefixedName ename) of
    "family_state" -> do
      fam <- lx (getTextFrom0 "family")
      return (OvalState sid (OvalStateOp (FamilyIs fam) Equal))
    "uname_state" -> do
      ver <- extractParameter "version" mp
      ignoreNested []
      return (OvalState sid (OvalStateOp (UnameIs ver) Equal))
    "rpmverifyfile_state" -> do
      nm <- lx (getTextFrom "name")
      -- TODO, assumes pattern match :/
      guard (nm == "^redhat-release" || nm == "^redhat-release-coreos")
      mversion <- lx (optional (getTextFrom "version"))
      case mversion of
        Just version -> pure (OvalState sid (OvalStateOp (Version version) PatternMatch))
        Nothing -> pure (OvalState sid (OvalStateOp Exists Equal))
    "dpkginfo_state" -> do
      nm <- lx (optional (getTextFrom "name"))
      lx $ element "evr" $ \emap -> do
        dt <- extractParameter "datatype" emap
        unless (dt == "debian_evr_string") (fail "Only debian_evr_string datatype is supported")
        OvalState sid <$> extractop (DpkgState nm) emap
    "rpminfo_state" -> do
      let evr = element "evr" $ \emap -> do
            dt <- extractParameter "datatype" emap
            unless (dt == "evr_string") (fail "Only evr_string datatype is supported")
            extractop (RpmState . parseRPMVersion . sanitizeVersion . T.unpack) emap
          sanitizeVersion x = case break (== ':') x of
            (_, ':' : o) -> o
            _ -> x
          version = element "version" (extractop Version)
          signatureKeyid = element "signature_keyid" (extractop SignatureKeyId)
          arch = element "arch" (extractop Arch)
      tests <- some (lx (evr <|> version <|> signatureKeyid <|> arch))
      return (OvalState sid (foldl1 AndStateOp tests))
    nm
      | "textfilecontent" `T.isPrefixOf` nm ->
        OvalState sid . (`OvalStateOp` Equal) . MiscTest nm
          <$> lx (getTextFrom "subexpression" <|> getTextFrom "text")
    _ -> fail ("Unknown state type: " ++ T.unpack ename)

extractop :: (T.Text -> TestType) -> HM.HashMap T.Text T.Text -> Parser OvalStateOp
extractop testtype emap = do
  op <- extractParameter "operation" emap >>= extractOperation
  txt <- mconcat <$> many characterdata
  return $ OvalStateOp (testtype txt) op

parsedoc :: Parser ([OvalDefinition], [OvalTest], [OvalObject], [OvalState])
parsedoc = lx $ element_ "oval_definitions" $ do
  lx (ignoreElement "generator")
  defs <- catMaybes <$> lx (element_ "definitions" (many definition P.<?> "many defintion"))
  tsts <- lx (element_ "tests" (many test))
  objs <- lx (element_ "objects" (many object))
  stts <- lx (element_ "states" (many state))
  void $ lx $ optional $ ignoreElement "variables" -- TODO, check what this is, this is for ubuntu xenial
  return (defs, tsts, objs, stts)

parseOvalStream :: FilePath -> BSL.ByteString -> Either String ([OvalDefinition], HM.HashMap OTestId OFullTest)
parseOvalStream filename l =
  case parseStream filename l (xml parsedoc <|> parsedoc) of
    Left rr -> Left rr
    Right (d, t, p, s) -> (d,) . HM.fromList <$> mkTests t p s

mkTests :: [OvalTest] -> [OvalObject] -> [OvalState] -> Either String [(OTestId, OFullTest)]
mkTests tests objects states = catMaybes <$> mapM mkTest tests
  where
    getFromMap t mp = case HM.lookup t mp of
      Just x -> Right x
      Nothing -> Left ("Could not lookup " <> show t)
    mkTest :: OvalTest -> Either String (Maybe (OTestId, OFullTest))
    mkTest t = case t of
      TestAlways testid b w -> pure $ Just (testid, OFullTest "always" (OvalStateOp (TTBool b w) Equal))
      RpmInfoT testid _ Nothing -> do
        traceM ("fixme, ignoreing testid " ++ show testid)
        pure Nothing
      RpmInfoT testid objectid (Just stateid) -> go testid objectid stateid
      FamilyT testid objectid stateid -> go testid objectid stateid
      UnameT testid objectid mstateid -> mgo testid objectid mstateid
      DpkgInfoT testid objectid mstateid -> mgo testid objectid mstateid
      VersionIs testid version -> pure $ Just (testid, OFullTest "distribution" (OvalStateOp (Version version) Equal))
      IVersionIs testid version -> pure $ Just (testid, OFullTest "distribution" (OvalStateOp (IVersion version) Equal))
      MVersionIs testid version ->
        pure $ Just (testid, OFullTest "distribution" (OvalStateOp (Version (reVersion version)) PatternMatch))
      UnknownT -> pure Nothing
      Unhandled _ _ _ td
        | Just mname <- T.stripPrefix "Module " (_tdCE td) >>= T.stripSuffix " is enabled" -> Nothing <$ traceM ("Unhandled RedHat module check for " ++ show mname)
        | Just mname <- T.stripPrefix "kernel version " (_tdCE td) >>= T.stripSuffix " is set to boot up on next boot" -> Nothing <$ traceM ("Unhandled RedHat next boot check for " ++ show mname)
      Unhandled {} -> Left ("Unknown test " ++ show t)
      where
        reVersion v = "^" <> T.pack (show v) <> "(\\.[.0-9]+)?$"
        go testid objectid stateid = do
          obj <- getFromMap objectid omap
          top <- getFromMap stateid smap
          when (T.null obj) (traceShowM top)
          pure $ Just (testid, OFullTest obj top)
        mgo testid objectid mstateid = do
          obj <- getFromMap objectid omap
          case mstateid of
            Nothing | T.null obj -> pure $ Just (testid, OFullTest "always" (OvalStateOp (TTBool True "no stateid, no obj") Equal))
            _ -> do
              top <- maybe (pure (OvalStateOp Exists Equal)) (`getFromMap` smap) mstateid
              pure $ Just (testid, OFullTest obj top)
    omap = HM.fromList $ map mkov objects
    mkov o = case o of
      RpmO oid t -> if T.null t then error (show oid) else (oid, t)
      DpkgO oid t -> if T.null t then error (show oid) else (oid, t)
      FamilyO oid -> (oid, "")
      UnameO oid -> (oid, "")
      ReleaseCodenameO oid -> (oid, "")
      FileContent oid _ _ _ -> (oid, "") -- TODO :(
    smap :: HM.HashMap StateId OvalStateOp
    smap = HM.fromList $ map (\(OvalState sid top) -> (sid, top)) states

parseOvalFile :: FilePath -> IO (Either String ([OvalDefinition], HM.HashMap OTestId OFullTest))
parseOvalFile fp = parseOvalStream fp <$> BSL.readFile fp

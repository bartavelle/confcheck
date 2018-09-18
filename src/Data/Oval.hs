{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Data.Oval ( parseOvalStream
                 , parseOvalFile
                 , OReference(..)
                 , OvalDefinition(..)
                 , OTestId(..)
                 , OFullTest(..)
                 , TestType(..)
                 , Operation(..)
                 , OvalStateOp(..)
                 , orRefid
                 , orRefurl
                 , orSource
                 , ovalDesc
                 , ovalReferences
                 , ovalRelease
                 , ovalSeverity
                 , ovalTitle
                 , ovalCond
                 , ovalId
                 , ovalLine
                 ) where

import Prelude
import qualified Text.Parsec.Prim as P
import qualified Text.Parsec.Pos as P
import Control.Monad
import Control.Applicative
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import Data.Monoid
import qualified Data.HashMap.Strict as HM
import Data.Hashable
import GHC.Generics hiding (to)
import Data.Serialize (Serialize(..))
import Data.Time.Calendar
import Data.Maybe (fromMaybe, catMaybes)
import Control.Lens hiding (element,op)
import Text.Read (readMaybe)

import Data.Parsers.Xml
import Data.Condition
import Analysis.Types

newtype ObjectId = ObjectId T.Text
                   deriving (Show, Eq, Hashable)
newtype StateId = StateId T.Text
                  deriving (Show, Eq, Hashable)
newtype OTestId = OTestId T.Text
                 deriving (Show, Eq, Hashable, Serialize)

data OReference = OReference { _orSource :: T.Text
                             , _orRefid  :: T.Text
                             , _orRefurl :: T.Text
                             } deriving (Show, Generic)

data Operator = CritAnd
              | CritOr
              deriving Show

data OvalDefinition = OvalDefinition { _ovalId         :: T.Text
                                     , _ovalTitle      :: T.Text
                                     , _ovalReferences :: [OReference]
                                     , _ovalDesc       :: T.Text
                                     , _ovalCond       :: Condition OTestId
                                     , _ovalSeverity   :: Severity
                                     , _ovalLine       :: Int
                                     , _ovalRelease    :: Day
                                     }
                                     deriving (Show, Generic)

instance Serialize OReference where
instance Serialize Operation where
instance Serialize TestType where
instance Serialize OFullTest where
instance Serialize OvalDefinition where
instance Serialize OvalStateOp where

data OvalTest = RpmInfoT !OTestId !ObjectId !StateId
              | FamilyT !OTestId !ObjectId !StateId
              | UnameT !OTestId !ObjectId !StateId
              | UnknownT
              | DpkgInfoT !OTestId !ObjectId !(Maybe StateId)
              | Unhandled !OTestId !ObjectId !StateId !TestDetails
              deriving Show

data TestDetails
    = TestDetails
    { _tdName    :: T.Text
    , _tdCheck   :: T.Text
    , _tdCE      :: T.Text
    , _tdComment :: T.Text
    } deriving Show

data OvalObject = RpmO !ObjectId !T.Text
                | FamilyO !ObjectId
                | UnameO !ObjectId
                | DpkgO !ObjectId !T.Text
                | ReleaseCodenameO !ObjectId
                deriving Show

data Operation = LessThan
               | Equal
               | PatternMatch
               | GreaterThanOrEqual
               deriving (Show, Generic, Eq)

data OvalState = OvalState !StateId !OvalStateOp
               deriving Show

data OvalStateOp
    = OvalStateOp !TestType !Operation
    | AndStateOp !OvalStateOp !OvalStateOp
    deriving (Show, Generic)

data TestType
    = RpmState       !RPMVersion
    | DpkgState      !T.Text !T.Text
    | Version        !T.Text
    | SignatureKeyId !T.Text
    | FamilyIs       !T.Text
    | UnameIs        !T.Text
    | Exists
    | MiscTest       !T.Text !T.Text
    | Arch           !T.Text
    deriving (Show, Generic, Eq)

data OFullTest
    = OFullTest
    { _ofulltestObject    :: !T.Text
    , _ofulltestOp        :: !OvalStateOp
    } deriving (Show, Generic)


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
      "Untriaged"  -> Right Unknown
      ""           -> Right Unknown
      "Not set"    -> Right Unknown
      "Negligible" -> Right None
      "Low"        -> Right Low
      "Medium"     -> Right Medium
      "Moderate"   -> Right Medium
      "Critical"   -> Right High
      "Important"  -> Right High
      "High"       -> Right High
      _            -> Left ("Unknown criticity " <> show t)

definition :: Parser (Maybe OvalDefinition)
definition = lx $ element "definition" $ \args ->
  case HM.lookup "class" args of
    Just "inventory" -> Nothing <$ (lx (ignoreElement "metadata") *> lx(ignoreElement "criteria"))
    _ -> do
      p <- P.getPosition
      defid <- extractParameter "id" args
      (title, refs, desc, msev) <- lx $ element_ "metadata" $ do
          title' <- lx $ getTextFrom "title"
          desc1 <- lx $ optional $ getTextFrom0 "description"
          lx $ ignoreElement "affected"
          refs' <- lx $ many (lx $ element "reference" (\mp -> OReference <$> extractParameter "source" mp
                                                                          <*> extractParameter "ref_id" mp
                                                                          <*> extractParameter "ref_url" mp))
          desc' <- maybe (lx $ getTextFrom "description") pure desc1
          msev' <- optional $ lx $ element_ "advisory" $ do
              cnt <- lx $ optional $ getTextFrom0 "severity"
              let ignoredElementsTags
                      = [ "rights"
                        , "cve"
                        , "bugzilla"
                        , "affected_cpe_list"
                        , "bug"
                        , "ref"
                        , "assigned_to"
                        , "public_date_at_usn"
                        , "discovered_by"
                        , "crd"
                        ]
                  ignoredElements = elementRPred (`elem` ignoredElementsTags) (const (ignoreNested [])) P.<?> "ignored metadata"
                  parsedDate =    elementRPred (`elem` ["issued", "updated"]) (extractParameter "date" >=> mkDate)
                              <|> lx (getTextFrom "public_date" >>= mkDate)
                              P.<?> "definition date"
                  mkDate dt = case mapM (readMaybe . T.unpack . T.takeWhile (/= ' ')) (T.splitOn "-" dt) of
                                  Just [y,m,d] -> pure $ fromGregorian y (fromIntegral m) (fromIntegral d)
                                  _ -> fail ("Can't parse date " <> show dt)
              mdays <- many (    (const Nothing <$> lx ignoredElements)
                             <|> (Just          <$> lx parsedDate))
              sev <- case cnt of
                       Nothing -> pure Unknown
                       Just txt -> either fail return (translateCriticity txt)
              return $ (sev,) $ case catMaybes mdays of
                                    (x : _) -> x
                                    _ -> fromGregorian 1970 1 1
          return (title', refs', desc', msev')
      P.skipMany $ ignoreElement "notes"
      crit <- criteria
      let (sev, res) = fromMaybe (Unknown, fromGregorian 1970 1 1) msev
      return $! Just $! OvalDefinition defid title refs desc crit sev (P.sourceLine p) res

object :: Parser OvalObject
object = lx (rpmObject <|> dpkgInfoObject <|> familyObject <|> unameObject <|> releaseCodenameObject)

dpkgInfoObject :: Parser OvalObject
dpkgInfoObject = element "dpkginfo_object"
  $ \mp -> DpkgO <$> (ObjectId <$> extractParameter "id" mp)
                 <*> lx (getTextFrom "name")

releaseCodenameObject :: Parser OvalObject
releaseCodenameObject = anyElement $ \ename mp -> do
  comment <- extractParameter "comment" mp
  oid <- ObjectId <$> extractParameter "id" mp
  ignoreNested []
  case comment of
    "The singleton release codename object." -> return (ReleaseCodenameO oid)
    _ -> fail ("Unknown object " ++ T.unpack comment ++ " in object " ++ T.unpack ename)

familyObject :: Parser OvalObject
familyObject = element "family_object" $ \mp -> UnameO <$> (ObjectId <$> extractParameter "id" mp)

unameObject :: Parser OvalObject
unameObject = element "uname_object" $ \mp -> UnameO <$> (ObjectId <$> extractParameter "id" mp)

rpmObject :: Parser OvalObject
rpmObject = element "rpminfo_object"
  $ \mp -> RpmO <$> (ObjectId <$> extractParameter "id" mp)
                <*> lx (getTextFrom "name")

test :: Parser OvalTest
test = lx (rpmtest <|> dpkgInfoTest <|> familyTest <|> unameTest <|> unknownTest <|> unhandledTest)

genTest :: T.Text -> (OTestId -> ObjectId -> StateId -> a) -> Parser a
genTest t c = element t $ \mp -> do
  rid <- OTestId <$> extractParameter "id" mp
  objid <- ObjectId <$> lx ( element "object" (extractParameter "object_ref") )
  sttid <- StateId  <$> lx ( element "state"  (extractParameter "state_ref") )
  return (c rid objid sttid)

rpmtest :: Parser OvalTest
rpmtest = genTest "rpminfo_test" RpmInfoT

unknownTest :: Parser OvalTest
unknownTest = UnknownT <$ ignoreElement "unknown_test"

unhandledTest :: Parser OvalTest
unhandledTest = anyElement $ \ename mp -> do
  rid <- OTestId <$> extractParameter "id" mp
  objid <- ObjectId <$> lx ( element "object" (extractParameter "object_ref") )
  sttid <- StateId  <$> lx ( element "state"  (extractParameter "state_ref") )
  details <- TestDetails ename <$> extractParameter "check" mp
                               <*> extractParameter "check_existence" mp
                               <*> extractParameter "comment" mp
  return (Unhandled rid objid sttid details)


familyTest :: Parser OvalTest
familyTest = genTest "family_test" FamilyT

unameTest :: Parser OvalTest
unameTest = genTest "uname_test" UnameT

dpkgInfoTest :: Parser OvalTest
dpkgInfoTest = element "dpkginfo_test" $ \mp -> do
  rid <- OTestId <$> extractParameter "id" mp
  objid <- ObjectId <$> lx ( element "object" (extractParameter "object_ref") )
  sttid <- optional (StateId  <$> lx ( element "state"  (extractParameter "state_ref") ))
  return (DpkgInfoT rid objid sttid)

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
    "dpkginfo_state" -> do
      nm <- lx (getTextFrom "name")
      lx $ element "evr" $ \emap -> do
        dt <- extractParameter "datatype" emap
        unless (dt == "debian_evr_string") (fail "Only debian_evr_string datatype is supported")
        OvalState sid <$> extractop (DpkgState nm) emap
    "rpminfo_state" -> do
      let evr = element "evr" $ \emap -> do
              dt <- extractParameter "datatype" emap
              unless (dt == "evr_string") (fail "Only evr_string datatype is supported")
              extractop (RpmState . parseRPMVersion . sanitizeVersion . T.unpack) emap
          sanitizeVersion x = case break (==':') x of
                                  (_, ':' : o) -> o
                                  _ -> x
          version = element "version" (extractop Version)
          signatureKeyid = element "signature_keyid" (extractop SignatureKeyId)
          arch = element "arch" (extractop Arch)
      tests <- some (lx (evr <|> version <|> signatureKeyid <|> arch))
      return (OvalState sid (foldl1 AndStateOp tests))
    nm | "textfilecontent" `T.isPrefixOf` nm -> do
      sub <- lx (getTextFrom "subexpression")
      return (OvalState sid (OvalStateOp (MiscTest nm sub) Equal))
    _ -> fail ("Unknown state type: " ++ T.unpack ename)
    -- (rpmState <|> dpkgState <|> familyState <|> unameState)

extractop :: (T.Text -> TestType) -> HM.HashMap T.Text T.Text -> Parser OvalStateOp
extractop testtype emap = do
  op <- extractParameter "operation" emap >>= extractOperation
  txt <- mconcat <$> many characterdata
  return $ OvalStateOp (testtype txt) op

parsedoc :: Parser ([OvalDefinition],[OvalTest],[OvalObject],[OvalState])
parsedoc = lx $ element_ "oval_definitions" $ do
  lx (ignoreElement "generator")
  defs <- catMaybes <$> lx (element_ "definitions" (many definition P.<?> "many defintion") )
  tsts <- lx (element_ "tests" (many test))
  objs <- lx (element_ "objects" (many object))
  stts <- lx (element_ "states" (many state))
  return (defs, tsts, objs, stts)

parseOvalStream :: FilePath -> BSL.ByteString -> Either String ([OvalDefinition], HM.HashMap OTestId OFullTest)
parseOvalStream filename l =
    case parseStream filename l (xml parsedoc <|> parsedoc) of
      Left rr -> Left rr
      Right (d,t,p,s) -> (d,) . HM.fromList <$> mkTests t p s

mkTests :: [OvalTest] -> [OvalObject] -> [OvalState] -> Either String [(OTestId, OFullTest)]
mkTests tests objects states = catMaybes <$> mapM mkTest tests
    where
        getFromMap t mp = case HM.lookup t mp of
                              Just x -> Right x
                              Nothing -> Left ("Could not lookup " <> show t)
        mkTest :: OvalTest -> Either String (Maybe (OTestId, OFullTest))
        mkTest t = case t of
          RpmInfoT testid objectid stateid   -> go testid objectid stateid
          FamilyT testid objectid stateid    -> go testid objectid stateid
          UnameT testid objectid stateid     -> go testid objectid stateid
          DpkgInfoT testid objectid mstateid -> do
            obj <- getFromMap objectid omap
            top <- maybe (pure (OvalStateOp Exists Equal)) (`getFromMap` smap) mstateid
            pure $ Just (testid, OFullTest obj top)
          UnknownT -> pure Nothing
          Unhandled _ _ _ details ->
            if _tdComment details `elem`
                  [ "Is the host running Ubuntu trusty?"
                  , "Is the host running Ubuntu xenial?"
                  ]
              then Right Nothing
              else Left ("Unknown test " ++ show t)
         where
            go testid objectid stateid = do
              obj <- getFromMap objectid omap
              top <- getFromMap stateid smap
              pure $ Just (testid, OFullTest obj top)
        omap = HM.fromList $ map mkov objects
        mkov o = case o of
                   RpmO oid t  -> (oid, t)
                   DpkgO oid t -> (oid, t)
                   FamilyO oid -> (oid, mempty)
                   UnameO oid  -> (oid, mempty)
                   ReleaseCodenameO oid -> (oid, mempty)
        smap :: HM.HashMap StateId OvalStateOp
        smap = HM.fromList $ map (\(OvalState sid top) -> (sid, top)) states

parseOvalFile :: FilePath -> IO (Either String ([OvalDefinition], HM.HashMap OTestId OFullTest))
parseOvalFile fp = parseOvalStream fp <$> BSL.readFile fp

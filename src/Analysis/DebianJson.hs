{-# LANGUAGE TemplateHaskell #-}
module Analysis.DebianJson where

import           Control.Lens
import           Data.Aeson
import qualified Data.HashMap.Strict as HM
import           Data.Text           (Text)

import           Prelude

type AllEntries = HM.HashMap Package CVEs
type CVEs = HM.HashMap Text CVEInfo

data DScope = Local | Remote
            deriving (Show, Eq)

data DStatus = DebOpen | DebResolved | DebUnknown
             deriving (Show, Eq)

instance FromJSON DStatus where
    parseJSON = withText "DStatus" $ \s -> case s of
                                               "open"         -> pure DebOpen
                                               "resolved"     -> pure DebResolved
                                               "unknown"      -> pure DebUnknown
                                               "undetermined" -> pure DebUnknown
                                               _ -> fail ("Dstatus:" ++ show s)

data DUrgency = MediumS | HighS | Low | Unimportant | EOL | NotYetAssigned | LowS | Medium | High
              deriving (Show, Eq)


instance ToJSON DScope where
    toJSON Local  = "local"
    toJSON Remote = "remote"

instance FromJSON DScope where
    parseJSON = withText "scope" $ \s -> case s of
                                              "local"  -> pure Local
                                              "remote" -> pure Remote
                                              _        -> fail (show s)

type ReleaseName = Text
type Package = Text

data CVEInfo = CVEInfo { _cviReleases    :: HM.HashMap ReleaseName FixInfo
                       , _cviDebianBug   :: Maybe Int
                       , _cviScope       :: Maybe DScope
                       , _cviDescription :: Maybe Text
                       } deriving (Show, Eq)

instance FromJSON CVEInfo where
    parseJSON = withObject "CVEInfo" $ \o -> CVEInfo <$> o .:  "releases"
                                                     <*> o .:? "debianbug"
                                                     <*> o .:? "scope"
                                                     <*> o .:? "description"

instance FromJSON DUrgency where
    parseJSON = withText "DUrgency" $ \s -> case s of
                                                "medium**"         -> pure MediumS
                                                "high**"           -> pure HighS
                                                "low**"            -> pure LowS
                                                "medium"           -> pure Medium
                                                "high"             -> pure High
                                                "low"              -> pure Low
                                                "end-of-life"      -> pure EOL
                                                "not yet assigned" -> pure NotYetAssigned
                                                "unimportant"      -> pure Unimportant
                                                _                  -> fail ("urgency: " ++ show s)

data FixInfo = FixInfo { _fiStatus       :: DStatus
                       , _fiNodsa        :: Maybe Text
                       , _fiUrgency      :: DUrgency
                       , _fiRepositories :: HM.HashMap Text Text
                       , _fiFixedVersion :: Maybe Text
                       } deriving (Show, Eq)

instance FromJSON FixInfo where
    parseJSON = withObject "FixInfo" $ \o -> FixInfo <$> o .: "status"
                                                     <*> o .:? "nodsa"
                                                     <*> o .: "urgency"
                                                     <*> o .: "repositories"
                                                     <*> o .:? "fixed_version"

makeLenses ''CVEInfo
makeLenses ''FixInfo

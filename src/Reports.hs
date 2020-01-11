{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE TemplateHaskell #-}
module Reports where

import           Control.Lens
import           Data.Sequence                             (Seq)
import           Data.Text                                 (Text)
import           Data.Text.Prettyprint.Doc
import           Data.Text.Prettyprint.Doc.Render.Terminal
import qualified Data.Text.Prettyprint.Doc.Render.Text     as T
import           GHC.Generics

import           Analysis.Types.Rhost
import           Analysis.Types.UnixUsers
import           Analysis.Types.Vulnerability

data DisplayMode
    = Raw
    | Ansi
    deriving (Show, Eq, Ord, Enum, Read, Bounded)

data VulnGroups
    = VulnGroups
    { _vgOutdated       :: !(Seq OutdatedPackage) -- ^ missing patches are merged here
    , _vgMultipleUser   :: !(Seq (Multiple PasswdEntry))
    , _vgMultipleGroup  :: !(Seq (Multiple GroupEntry))
    , _vgMultipleShadow :: !(Seq (Multiple ShadowEntry))
    , _vgRHost          :: !(Seq Rhost)
    , _vgFile           :: !(Seq FileVuln)
    , _vgMisc           :: !(Seq Text)
    , _vgSysctl         :: !(Seq WrongSysctl)
    } deriving (Show, Eq, Generic)

makeLenses 'VulnGroups

showReport
  :: DisplayMode
  -> Seq Vulnerability
  -> IO ()
showReport mode = displayFunc . showPart . regroup
  where
    displayFunc =
      case mode of
        Raw  -> T.putDoc
        Ansi -> putDoc

regroup
  :: Seq Vulnerability
  -> VulnGroups
regroup = undefined

showPart
  :: VulnGroups
  -> Doc AnsiStyle
showPart _ = undefined

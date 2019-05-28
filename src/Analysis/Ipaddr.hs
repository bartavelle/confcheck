module Analysis.Ipaddr (anaIpaddr) where

import Analysis.Types
import Analysis.Common

import Data.Text (Text)
import Data.Sequence (Seq)
{-
import Data.Maybe (mapMaybe)
import qualified Data.Text as T
import qualified Data.Sequence as Seq
import Network.IP.Addr
import Data.Textual
import Data.Char (isAlphaNum)
import Control.Lens
import Control.Applicative
import Control.Monad
import Data.Bits
import qualified Data.Vector as V
-}

anaIpaddr :: Analyzer (Seq ConfigInfo)
anaIpaddr = parseIpaddr <$> requireTxt ["reseau/ifconfig-a.txt"]

parseIpaddr :: Text -> Seq ConfigInfo
parseIpaddr = undefined

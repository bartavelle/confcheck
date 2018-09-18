{-# LANGUAGE OverloadedStrings #-}
module Analysis.LinuxKern (anaKernel) where

import Analysis.Types
import Analysis.Common
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Text (Text)
import qualified Data.Text as T
import Control.Lens
import Data.Monoid

anaKernel :: Analyzer (Seq ConfigInfo)
anaKernel = parseVersion <$> requireTxt ["etat/version.txt"]

parseVersion :: Text -> Seq ConfigInfo
parseVersion ver = Seq.singleton (KernelVersion (T.strip ver)) <> arch
    where
        arch = maybe mempty (Seq.singleton . Architecture) $ lastOf (to T.words . ix 2 . to (T.splitOn ".") . traverse) ver


module Data.Common where

import Control.Arrow
import qualified Data.Map.Strict as M

regroupMap :: Ord k => (a -> k) -> (a -> v) -> [a] -> M.Map k [v]
regroupMap getkey getval = M.fromListWith (++) . map (getkey &&& (pure . getval))

module Data.Common where

import qualified Data.Map.Strict as M
import Control.Arrow

regroupMap :: Ord k => (a -> k) -> (a -> v) -> [a] -> M.Map k [v]
regroupMap getkey getval = M.fromListWith (++) . map (getkey &&& (pure . getval))

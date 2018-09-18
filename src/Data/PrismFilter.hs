{-# LANGUAGE RankNTypes #-}
module Data.PrismFilter where

import Prelude
import qualified Control.Foldl as F
import Control.Lens

maybeFold :: (Applicative m, Monoid (m b)) => (a -> Maybe b) -> F.Fold a (m b)
maybeFold f = F.foldMap (maybe mempty pure . f) id

prismFold :: (Applicative m, Monoid (m b)) => Prism' a b -> F.Fold a (m b)
prismFold p = maybeFold (preview p)

runfold :: F.Foldable f => F.Fold a b -> f a -> b
runfold = F.fold

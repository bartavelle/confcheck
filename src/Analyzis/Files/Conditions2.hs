module Analyzis.Files.Conditions2 where

import qualified Data.HashSet as HS
import Control.Lens
import Control.Monad
import Data.List
import qualified Data.Text.Encoding as T
import qualified Data.Sequence as Seq
import qualified Data.Foldable as F
import qualified Data.ByteString.Char8 as BS
import qualified System.Posix.FilePath as FP
import qualified Data.Maybe.Strict as S
import Data.Maybe (mapMaybe)
import qualified Data.Text as T
import qualified Data.CompactMap as CM
import qualified Data.Map.Strict as M
import Control.Applicative
import GHC.Exts (sortWith)
import Data.Text (Text)
import Data.Sequence (Seq)
import Data.Maybe (fromMaybe)
import Control.Monad.State.Strict
import Data.Monoid

import Analyzis.Types
import Analyzis.Files.Conditions
import Data.Condition
import Analyzis.Common

data FileTree = Leaf !UnixFileParse
              | Dir !UnixFileParse !(M.Map FP FileTree)
              deriving (Show, Eq)

getF :: FileTree -> UnixFileParse
getF f = case f of
             Leaf x -> x
             Dir x _ -> x

toFileTree :: [ UnixFileParse ] -> Either Text FileTree
toFileTree [] = Left "toFileTree: empty input"
toFileTree (root : allfiles) | _filePath root /= "/" = error "toFileTree: doesn't start with /"
                             | otherwise = let (result, remaining) = runState (mkTree root ) allfiles
                                           in  if null remaining
                                                   then Right result
                                                   else error (show result) -- Left ("toFileTree: remaining elements - " <> T.pack (show (length remaining)))

peekWithPrefix :: FP -> State [ UnixFileParse ] (Maybe UnixFileParse)
peekWithPrefix fp = StateT $ \lst -> return $ case lst of
                                        [] -> (Nothing, lst)
                                        (curfile:nextfiles) -> if fp `BS.isPrefixOf` _filePath curfile
                                                                   then (Just curfile, nextfiles)
                                                                   else (Nothing, lst)

mkTree :: UnixFileParse -> State [ UnixFileParse ] FileTree
mkTree f | _fileType f /= TDirectory = pure (Leaf f)
         | otherwise = do
             let path = _filePath f
             mp <- getSubfiles path
             return (Dir f mp)

getSubfiles :: FP -> State [ UnixFileParse ] (M.Map FP FileTree)
getSubfiles fp = do
    let nextsub = peekWithPrefix dirname >>= \mf -> case mf of
                                                   Nothing -> return []
                                                   Just f  -> (:) <$> mkTree f <*> nextsub
        dirname = if fp == "/"
                      then fp
                      else fp <> "/"
    subs <- nextsub
    return (M.fromList [ (_filePath (getF f), f) | f <- subs ])

fileCondition :: [ CheckCondition ] -> [ UnixFileParse ] -> Seq Vulnerability
fileCondition conditions filelist = either (Seq.singleton . ConfigInformation . ConfigError . MiscError) (checkConditions conditions) (toFileTree filelist)

checkConditions :: [ CheckCondition ] -> FileTree -> Seq Vulnerability
checkConditions = undefined


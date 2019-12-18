{-# LANGUAGE OverloadedStrings #-}
module Main where

import System.Environment
import qualified Data.HashMap.Strict as HM
import qualified Data.Text as T
import qualified Data.Text.IO as TIO

import Data.Oval
import Data.Condition
import Analysis.Types (RPMVersion(..))

main :: IO ()
main = getArgs >>= mapM_ showOvalFile

showOvalFile :: FilePath -> IO ()
showOvalFile fp = parseOvalFile fp >>= TIO.putStrLn . either (T.pack . show) describe

describe :: ([OvalDefinition], HM.HashMap OTestId OFullTest) -> T.Text
describe (defs, tests) = T.unlines (map showDef defs)
  where
    showDef odef = T.unlines ((_ovalId odef <> " " <> _ovalTitle odef) : descCond 2 (_ovalCond odef))
    indent ind s = T.replicate ind " " <> s
    descTest (OFullTest tobj top) =
      case top of
        AndStateOp a b -> descTest (OFullTest tobj a) <> " && " <> descTest (OFullTest tobj b)
        OvalStateOp Exists Equal ->
          "package " <> tobj <> " exists"
        OvalStateOp (DpkgState mt v) LessThan ->
          "package " <> tobj <> " <= " <> v <> foldMap (\x -> " [" <> x <> "]") mt
        OvalStateOp (RpmState rversion) LessThan ->
          "package " <> tobj <> " <= " <> T.pack (getRPMString rversion)
        OvalStateOp (Arch ptrn) PatternMatch ->
          "arch =~ " <> ptrn
        OvalStateOp (Version n) Equal ->
          "distribution version " <> n
        OvalStateOp (TTBool x r) Equal ->
          "*ALWAYS* " <> (if x then "TRUE" else "FALSE") <> " " <> r
        _ -> T.pack (show (tobj, top))
    descCond ind c =
      case c of
        Pure testid@(OTestId ttxt) ->
          case HM.lookup testid tests of
            Nothing -> ["??? " <> ttxt]
            Just tst -> [indent ind $ descTest tst]
        Always b -> [indent ind ("Always " <> if b then "True" else "False")]
        Not c' -> indent ind "not" : descCond (ind + 2) c'
        And conds -> indent ind "and" : concatMap (descCond (ind + 2)) conds
        Or conds -> indent ind "or" : concatMap (descCond (ind + 2)) conds

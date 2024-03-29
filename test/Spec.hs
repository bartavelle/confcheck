{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Analysis.Parsers as P
import Test.Tasty
import Test.Tasty.HUnit
import qualified Text.Megaparsec as P

testTimeParser :: TestTree
testTimeParser = testCase "parsec time parser" $ assertEqual "time" expected actual
  where
    expected = Right ((4 * 60 + 42) * 60 + 16.465)
    actual = P.parse P.parseTimeMs "dummy" "4:42:16.465"

main :: IO ()
main =
  defaultMain $
    testGroup
      "main"
      [ testTimeParser
      ]

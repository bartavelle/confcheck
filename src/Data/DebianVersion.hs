{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE FlexibleContexts #-}

-- pompé du module debian

module Data.DebianVersion
  ( DebianVersion,
    parseDebianVersion,
    prettyDebianVersion,
    version,
    revision,
  )
where

import Analysis.Parsers
import Control.Monad
import Data.Char
import Data.Data (Data)
import qualified Data.Text as T
import Data.Typeable (Typeable)
import Text.Megaparsec
import Text.Megaparsec.Char
import Text.Regex

data DebianVersion
  = DebianVersion String (Found Int, NonNumeric, Found NonNumeric)
  deriving (Data, Typeable)

instance Show DebianVersion where
  show (DebianVersion v _) = "(Debian.Version.parseDebianVersion (" ++ show v ++ " :: String))"

prettyDebianVersion :: DebianVersion -> String
prettyDebianVersion (DebianVersion v _) = v

data NonNumeric
  = NonNumeric String (Found Numeric)
  deriving (Show, Data, Typeable)

data Numeric
  = Numeric Int (Maybe NonNumeric)
  deriving (Show, Data, Typeable)

data Found a
  = Found {unFound :: a}
  | Simulated {unFound :: a}
  deriving (Show, Data, Typeable)

instance (Eq a) => Eq (Found a) where
  f1 == f2 = unFound f1 == unFound f2

instance (Ord a) => Ord (Found a) where
  compare f1 f2 = compare (unFound f1) (unFound f2)

instance Eq DebianVersion where
  (DebianVersion _ v1) == (DebianVersion _ v2) = v1 == v2

instance Ord DebianVersion where
  compare (DebianVersion _ v1) (DebianVersion _ v2) = compare v1 v2

instance Eq NonNumeric where
  (NonNumeric s1 n1) == (NonNumeric s2 n2) =
    case compareNonNumeric s1 s2 of
      EQ -> n1 == n2
      _o -> False

instance Ord NonNumeric where
  compare (NonNumeric s1 n1) (NonNumeric s2 n2) =
    case compareNonNumeric s1 s2 of
      EQ -> compare n1 n2
      o -> o

instance Eq Numeric where
  (Numeric n1 mnn1) == (Numeric n2 mnn2) =
    case compare n1 n2 of
      EQ -> case compareMaybeNonNumeric mnn1 mnn2 of
        EQ -> True
        _ -> False
      _ -> False

compareNonNumeric :: String -> String -> Ordering
compareNonNumeric "" "" = EQ
compareNonNumeric "" ('~' : _cs) = GT
compareNonNumeric ('~' : _cs) "" = LT
compareNonNumeric "" _ = LT
compareNonNumeric _ "" = GT
compareNonNumeric (c1 : cs1) (c2 : cs2) =
  if order c1 == order c2
    then compareNonNumeric cs1 cs2
    else compare (order c1) (order c2)

order :: Char -> Int
order c
  | isDigit c = 0
  | isAlpha c = ord c
  | c == '~' = -1
  | otherwise = ord c + 256

compareMaybeNonNumeric :: Maybe NonNumeric -> Maybe NonNumeric -> Ordering
compareMaybeNonNumeric mnn1 mnn2 =
  case (mnn1, mnn2) of
    (Nothing, Nothing) -> EQ
    (Just (NonNumeric nn _), Nothing) -> compareNonNumeric nn ""
    (Nothing, Just (NonNumeric nn _)) -> compareNonNumeric "" nn
    (Just nn1, Just nn2) -> compare nn1 nn2

instance Ord Numeric where
  compare (Numeric n1 mnn1) (Numeric n2 mnn2) =
    case compare n1 n2 of
      EQ -> compareMaybeNonNumeric mnn1 mnn2
      o -> o

-- | Split a DebianVersion into its three components: epoch, version,
--  revision.  It is not safe to use the parsed version number for
--  this because you will lose information, such as leading zeros.
evr :: DebianVersion -> (Maybe Int, String, Maybe String)
evr (DebianVersion s _) =
  let re = mkRegex "^(([0-9]+):)?(([^-]*)|((.*)-([^-]*)))$"
   in --                 (         ) (        (            ))
      --                  (   e  )    (  v  )  (v2) (  r  )
      case matchRegex re s of
        Just ["", _, _, v, "", _, _] -> (Nothing, v, Nothing)
        Just ["", _, _, _, _, v, r] -> (Nothing, v, Just r)
        Just [_, e, _, v, "", _, _] -> (Just (read e), v, Nothing)
        Just [_, e, _, _, _, v, r] -> (Just (read e), v, Just r)
        -- I really don't think this can happen.
        _ -> error ("Invalid Debian Version String: " ++ s)

parseDebianVersion :: T.Text -> Either (ParseErrorBundle T.Text Void) DebianVersion
parseDebianVersion t = case parse prs "version" t of
  Left rr -> Left rr
  Right evr' -> Right (DebianVersion (T.unpack t) evr')
  where
    prs = do
      skipMany (oneOf (" \t" :: String))
      e <- parseEpoch
      upstreamVersion <- parseNonNumeric True True
      debianRevision <- option (Simulated (NonNumeric "" (Simulated (Numeric 0 Nothing)))) (char '-' >> parseNonNumeric True False >>= return . Found)
      return (e, upstreamVersion, debianRevision)

parseEpoch :: Parser (Found Int)
parseEpoch =
  option (Simulated 0) (try (some digitChar >>= \d -> char ':' >> return (Found (read d))))

parseNonNumeric :: Bool -> Bool -> Parser NonNumeric
parseNonNumeric zeroOk upstream =
  do
    nn <- (if zeroOk then many else some) (noneOf ("-0123456789" :: String) <|> if upstream then upstreamDash else mzero)
    n <- parseNumeric upstream
    return $ NonNumeric nn n
  where
    upstreamDash :: Parser Char
    upstreamDash = try $ do
      void (char '-')
      void (lookAhead (many (noneOf ("- \n\t" :: String)) >> char '-'))
      return '-'

parseNumeric :: Bool -> Parser (Found Numeric)
parseNumeric upstream =
  do
    n <- some (satisfy isDigit)
    nn <- option Nothing (parseNonNumeric False upstream >>= return . Just)
    return $ Found (Numeric (read n) nn)
    <|> return (Simulated (Numeric 0 Nothing))

version :: DebianVersion -> String
version v = case evr v of (_, x, _) -> x

revision :: DebianVersion -> Maybe String
revision v = case evr v of (_, _, x) -> x

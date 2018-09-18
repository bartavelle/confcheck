{-# LANGUAGE RankNTypes #-}
module Analysis.Parsers (parseInt, parseDateYMD, parseTimeMs, lx, parseUnixUser, parseToConfigInfoMT, parseEnglishMonth, parseToConfigInfoND, parseErrorToConfigInfo, parseErrorToCError, hexValue) where

import Prelude
import Analysis.Types
import Text.Parsec.Combinator
import Text.Parsec.Char
import Text.Parsec.Text
import Text.Parsec.Prim (try)
import Control.Applicative
import qualified Data.Text as T
import Data.Char (isAlphaNum, isDigit, digitToInt)
import Text.Parsec.Error
import Text.Parsec.Pos
import Data.Time
import qualified Data.Sequence as Seq
import Data.List (foldl')

import qualified Data.Parsers.Helpers as H

parseInt :: (Num b, Read b, Integral b) => Parser b
parseInt = read <$> many1 digit

lx :: Parser a -> Parser a
lx p = p <* spaces

parseErrorToConfigInfo :: Maybe T.Text -> ParseError -> ConfigInfo
parseErrorToConfigInfo o rr = ConfigError (ParsingError (T.pack (sourceName (errorPos rr))) (show rr) o)

parseToConfigInfoMT :: (a -> ConfigInfo) -> [T.Text] -> [Either ParseError a] -> Seq.Seq ConfigInfo
parseToConfigInfoMT f lst = Seq.fromList . zipWith tci lst
    where
        tci o (Left rr) = parseErrorToConfigInfo (Just o) rr
        tci _ (Right a) = f a

parseErrorToCError :: ParseError -> CError
parseErrorToCError rr = ParsingError (T.pack (sourceName (errorPos rr))) (show rr) Nothing

parseToConfigInfoND :: (a -> ConfigInfo) -> [Either ParseError a] -> Seq.Seq ConfigInfo
parseToConfigInfoND f = Seq.fromList . map tci
    where
        tci (Left rr) = ConfigError $ parseErrorToCError rr
        tci (Right a) = f a

-- format YYYY-MM-DD
parseDateYMD :: Parser Day
parseDateYMD = fromGregorian <$> (parseInt <* char '-')
                             <*> (parseInt <* char '-')
                             <*> parseInt

parseEnglishMonth :: Parser Int
parseEnglishMonth = try ( ((\u l1 l2 -> [u,l1,l2]) <$> upper <*> lower <*> lower) >>= H.englishMonth)

-- format HH:MM:SS.XXXXXXXX
parseTimeMs :: Parser DiffTime
parseTimeMs = do
    h <- parseInt <* char ':' :: Parser Integer
    m <- parseInt <* char ':' :: Parser Integer
    s <- many1 digit <* char '.'
    micro <- many1 digit
    let ms :: Double
        ms = read (s ++ "." ++ micro)
        pico = 1000000000000
        ps :: Integer
        ps = truncate (ms * fromIntegral pico)
        totaltime :: Integer
        totaltime = (h * 60 + m) * 60 * pico + ps
    return (picosecondsToDiffTime totaltime)

parseUnixUser :: Parser T.Text
parseUnixUser = do
    first <- satisfy isAlphaNum
    rst <- many $ satisfy $ if isDigit first
                                then isDigit
                                else (\x -> isAlphaNum x || x == '_')
    return (T.pack (first : rst))

hexValue :: Parser Int
hexValue = foldl' (\c n -> c * 16 + digitToInt n) 0 <$> some hexDigit

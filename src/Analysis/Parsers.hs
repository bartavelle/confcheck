{-# LANGUAGE RankNTypes #-}
module Analysis.Parsers
 ( parseInt
 , parseDateYMD
 , parseTimeMs
 , lx
 , parseUnixUser
 , parseToConfigInfoMT
 , parseEnglishMonth
 , parseToConfigInfoND
 , parseErrorToConfigInfo
 , parseErrorToCError
 , hexValue
 , textual
 , Parser
 , Void
 , stringLiteral
 , symbolic
 , decimal
 , parens
 , brackets
 , braces
 ) where

import           Analysis.Types
import           Data.Char                  (digitToInt, isAlphaNum, isDigit)
import           Data.List                  (foldl')
import qualified Data.Parsers.Helpers       as H
import qualified Data.Sequence              as Seq
import           Data.String                (IsString)
import           Data.Text                  (Text)
import qualified Data.Text                  as T
import qualified Data.Textual               as Textual
import           Data.Time
import           Data.Void                  (Void)
import           Text.Megaparsec
import           Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer
import qualified Text.Megaparsec.Parsers    as TP
import qualified Text.Parser.Token          as Tok

import           Prelude

type Parser = Parsec Void Text

textual :: Textual.Textual a => Parser a
textual = TP.unParsecT Textual.textual

stringLiteral :: IsString s => Parser s
stringLiteral = TP.unParsecT Tok.stringLiteral

symbolic :: Char -> Parser Char
symbolic = TP.unParsecT . Tok.symbolic

parens :: Parser a -> Parser a
parens = TP.unParsecT . Tok.parens . TP.ParsecT

brackets :: Parser a -> Parser a
brackets = TP.unParsecT . Tok.brackets . TP.ParsecT

braces :: Parser a -> Parser a
braces = TP.unParsecT . Tok.braces . TP.ParsecT

parseInt :: (Num b, Read b, Integral b) => Parser b
parseInt = Text.Megaparsec.Char.Lexer.decimal

decimal :: Parser Integer
decimal = TP.unParsecT Tok.decimal

lx :: Parser a -> Parser a
lx p = p <* space

parseErrorToConfigInfo :: Maybe T.Text -> ParseErrorBundle Text Void -> ConfigInfo
parseErrorToConfigInfo o rr = ConfigError (ParsingError "TODO megaparsec migration" (errorBundlePretty rr) o)

parseToConfigInfoMT :: (a -> ConfigInfo) -> [T.Text] -> [Either (ParseErrorBundle Text Void) a] -> Seq.Seq ConfigInfo
parseToConfigInfoMT f lst = Seq.fromList . zipWith tci lst
    where
        tci o (Left rr) = parseErrorToConfigInfo (Just o) rr
        tci _ (Right a) = f a

parseErrorToCError :: ParseErrorBundle Text Void -> CError
parseErrorToCError rr = ParsingError "TODO megaparsec migration" (errorBundlePretty rr) Nothing

parseToConfigInfoND :: (a -> ConfigInfo) -> [Either (ParseErrorBundle Text Void) a] -> Seq.Seq ConfigInfo
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
parseEnglishMonth = try ( ((\u l1 l2 -> [u,l1,l2]) <$> upperChar <*> lowerChar <*> lowerChar) >>= H.englishMonth)

-- format HH:MM:SS.XXXXXXXX
parseTimeMs :: Parser DiffTime
parseTimeMs = do
    h <- parseInt <* char ':' :: Parser Integer
    m <- parseInt <* char ':' :: Parser Integer
    s <- some digitChar <* char '.'
    micro <- some digitChar
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
hexValue = foldl' (\c n -> c * 16 + digitToInt n) 0 <$> some hexDigitChar

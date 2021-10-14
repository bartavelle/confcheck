{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE RankNTypes #-}

module Analysis.Parsers.Megaparsec where

import Control.Applicative
import qualified Data.List.NonEmpty as NonEmpty
import Data.Text (Text)
import qualified Data.Text as T
import Data.Void (Void)
import qualified Text.Megaparsec as Parsec
import qualified Text.Megaparsec.Char as Parsec
import Text.Parser.Char
import Text.Parser.Combinators
import qualified Text.Parser.Token as Tok

type Parser = Parsec.Parsec Void Text

newtype TXT a = TXT {unT :: Parser a}
  deriving (Functor, Applicative, Alternative, Monad) via Parser

instance CharParsing TXT where
  {-# INLINE satisfy #-}
  satisfy = TXT . Parsec.satisfy
  {-# INLINE char #-}
  char = TXT . Parsec.char
  {-# INLINE string #-}
  string = TXT . fmap T.unpack . Parsec.string . T.pack
  {-# INLINE text #-}
  text = TXT . Parsec.string
  {-# INLINE notChar #-}
  notChar = TXT . Parsec.anySingleBut
  {-# INLINE anyChar #-}
  anyChar = TXT Parsec.anySingle

instance Tok.TokenParsing TXT

instance Parsing TXT where
  {-# INLINE try #-}
  try = TXT . Parsec.try . unT

  {-# INLINE (<?>) #-}
  a <?> b = TXT (unT a Parsec.<?> b)

  {-# INLINE notFollowedBy #-}
  notFollowedBy = TXT . Parsec.notFollowedBy . unT

  {-# INLINE eof #-}
  eof = TXT Parsec.eof

  {-# INLINE unexpected #-}
  unexpected = TXT . Parsec.unexpected . Parsec.Label . NonEmpty.fromList

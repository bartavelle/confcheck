{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
module Data.Serialize.Tdb (tdbEntries,parseElems) where

import Prelude
import Data.Serialize.Get
import qualified Data.ByteString as BS
import Control.Monad
import Control.Applicative
import Data.List (sort)
import Data.Word
import qualified Data.HashMap.Strict as HM

readDataAt :: (Int, [STR]) -> Int -> Get (Int, [STR])
readDataAt (curpos, curlst) offset = do
    skip (offset - curpos)
    skip 4
    sz <- fromIntegral <$> getWord32le
    cnt <- getBytes sz
    return (offset + sz + 8, cnt : curlst)

tdbEntries :: BS.ByteString -> Either String [STR]
tdbEntries = runGet $ do
    magic <- getBytes 32
    guard (BS.takeWhile (/= 0) magic == "TDB file\n")
    void getWord32le -- version
    hashSize <- fromIntegral <$> getWord32le
    skip 4 -- rwlocks
    skip 4 -- recovery
    skip 4 -- sequence number
    skip 4 -- magic hash 1
    skip 4 -- magic hash 2
    skip (27 * 4)
    offsets <- sort . filter (/= 0) . map fromIntegral <$> replicateM hashSize getWord32le
    let curpos = 32 + (27 + 7) * 4 + hashSize * 4
    snd <$> foldM readDataAt (curpos, []) offsets

type STR = BS.ByteString

nullstring :: Get STR
nullstring = BS.pack <$> gw
    where
        gw :: Get [Word8]
        gw = do
            n <- getWord8
            if n == 0
                then return []
                else (n:) <$> gw

parseElems :: STR -> Either String (STR, HM.HashMap STR (HM.HashMap STR [STR]))
parseElems e = case runGet myp e of
                   Left rr -> Left rr
                   Right (k,x) -> Right (if BS.null k then k else BS.init k, HM.fromList x)
    where
        blob :: Get (STR, HM.HashMap STR [STR])
        blob = do
            nbelems <- fromIntegral <$> getWord32le
            (,) <$> nullstring
                <*> (HM.fromList <$> replicateM nbelems plm)
        plm :: Get (STR, [STR])
        plm = do
            k <- nullstring
            n <- getWord32le
            (k,) <$> replicateM (fromIntegral n)
                        ((getWord32le >>= getByteString . fromIntegral) <* getWord8)
        myp :: Get (STR, [(STR, HM.HashMap STR [STR])])
        myp = do
            keylen <- fromIntegral <$> getWord32le
            skip 12
            key <- getBytes keylen
            skip 4
            (key,) <$> many blob

{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module Analyzis.TarStream (analyzeTar, analyzeTarGz, tarAnalyzer) where

import Data.Conduit
import qualified Data.Conduit.List      as CL
import qualified Data.Conduit.Binary    as CB
import qualified Data.Conduit.Zlib      as CZ
import qualified Data.Conduit.Tar       as CT
import qualified Data.ByteString        as BS
import qualified Data.Text              as T
import Control.Monad.Primitive (PrimMonad)
import Control.Monad.Base (MonadBase)
import Control.Lens
import Control.Monad.Trans.Resource (MonadResource)
import Control.Monad.Catch

import Control.Dependency
import Data.Conduit.Require

nestedTarProducer :: (PrimMonad base, MonadBase base m, MonadThrow m) => Conduit BS.ByteString m ([T.Text], BS.ByteString)
nestedTarProducer = CT.untar =$ CT.withEntries ( \hdr -> case CT.headerFileType hdr of
                                                             CT.FTNormal -> extract hdr
                                                             _ -> return ()
                                               )
    where
        extract hdr | ".tar.gz" `T.isSuffixOf` path = tgz
                    | ".tgz"    `T.isSuffixOf` path = tgz
                    | ".tar"    `T.isSuffixOf` path = tar
                    | otherwise = CL.consume >>= yield . ([path],) . mconcat
            where
                path = T.pack (CT.headerFilePath hdr)
                tgz = CZ.ungzip =$ tar
                tar = nestedTarProducer =$ CL.map (_1 %~ (path:))

tarAnalyzer :: (PrimMonad base, MonadBase base m, MonadThrow m) => [(RunMode, Require [T.Text] BS.ByteString a)] -> Conduit BS.ByteString m a
tarAnalyzer analyzers = nestedTarProducer =$ CL.map (_1 . ix 0 %~ dropHostname) =$ withRequirement analyzers fst (return . snd)
    where
        dropHostname = c . T.dropWhile (/='/')
        c x | T.null x  = ""
            | otherwise = T.tail x

analyzeTar :: (MonadResource m, MonadThrow m, Monoid a) => [(RunMode, Require [T.Text] BS.ByteString a)] -> FilePath -> m a
analyzeTar analyzers tarfile = CB.sourceFile tarfile =$ tarAnalyzer analyzers $$ CL.foldMap id

analyzeTarGz :: (MonadResource m, MonadThrow m, Monoid a) => [(RunMode, Require [T.Text] BS.ByteString a)] -> FilePath -> m a
analyzeTarGz analyzers tarfile = CB.sourceFile tarfile =$ CZ.ungzip =$ tarAnalyzer analyzers $$ CL.foldMap id


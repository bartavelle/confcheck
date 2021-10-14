{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TupleSections #-}

module Analysis.TarStream
  ( analyzeTar,
    analyzeTarGz,
    tarAnalyzer,
  )
where

import Control.Dependency
import Control.Lens
import Control.Monad.Catch
import Control.Monad.Primitive (PrimMonad)
import Control.Monad.Trans.Resource (MonadResource)
import qualified Data.ByteString as BS
import Data.Conduit
import qualified Data.Conduit.Binary as CB
import qualified Data.Conduit.List as CL
import Data.Conduit.Require
import qualified Data.Conduit.Tar as CT
import qualified Data.Conduit.Zlib as CZ
import qualified Data.Text as T

nestedTarProducer :: (MonadThrow m, PrimMonad m) => ConduitT BS.ByteString ([T.Text], BS.ByteString) m ()
nestedTarProducer = CT.untarChunks .| CT.withEntries inner
  where
    inner hdr = case CT.headerFileType hdr of
      CT.FTNormal -> extract hdr
      _ -> return ()
    extract hdr
      | ".tar.gz" `T.isSuffixOf` path = tgz
      | ".tgz" `T.isSuffixOf` path = tgz
      | ".tar" `T.isSuffixOf` path = tar
      | otherwise = CL.consume >>= yield . ([path],) . mconcat
      where
        bpath = CT.headerFilePath hdr
        path = T.pack bpath
        tgz = CZ.ungzip .| tar
        tar = nestedTarProducer .| CL.map (_1 %~ (path :))

tarAnalyzer :: (MonadThrow m, PrimMonad m) => [(RunMode, Require [T.Text] BS.ByteString a)] -> ConduitT BS.ByteString a m ()
tarAnalyzer analyzers = nestedTarProducer .| CL.map (_1 . ix 0 %~ dropHostname) .| withRequirement analyzers fst (return . snd)
  where
    dropHostname = c . T.dropWhile (/= '/')
    c x
      | T.null x = ""
      | otherwise = T.tail x

analyzeTar :: (MonadResource m, MonadThrow m, Monoid a, PrimMonad m) => [(RunMode, Require [T.Text] BS.ByteString a)] -> FilePath -> m a
analyzeTar analyzers tarfile = runConduit (CB.sourceFile tarfile .| tarAnalyzer analyzers .| CL.foldMap id)

analyzeTarGz :: (MonadResource m, MonadThrow m, Monoid a, PrimMonad m) => [(RunMode, Require [T.Text] BS.ByteString a)] -> FilePath -> m a
analyzeTarGz analyzers tarfile = runConduit (CB.sourceFile tarfile .| CZ.ungzip .| tarAnalyzer analyzers .| CL.foldMap id)

{-# LANGUAGE FlexibleContexts #-}
module Analysis.Shell (toCommands) where


import ShellCheck.Parser
import ShellCheck.AST
import ShellCheck.Interface
import Control.Monad.Writer
import Control.Monad.Identity (Identity(..))
import Data.List (nub)

data Command = Command { _cmdpath :: FilePath
                       , _cmdargs :: [String]
                       }
                       deriving (Show, Eq)

toparam :: Token -> String
toparam = concat . execWriter . doAnalysis f
    where
        f (T_Literal _ x) = tell [x]
        f _ = return ()

extractCommands :: Token -> [Command]
extractCommands = nub . execWriter . doAnalysis f
    where
        f (T_SimpleCommand _ _  (T_NormalWord _ [T_Literal _ b]:toks)) = tell [Command b (map toparam toks)]
        f _ = return ()

extractParams :: Command -> [FilePath]
extractParams (Command cmd prms) =
    cmd : case cmd of
              "." -> prms
              "source" -> prms
              "start-stop-daemon" -> take 1 (drop 1 (dropWhile (/= "--exec") prms))
              _ -> []

toCommands :: FilePath -> String -> Either String [FilePath]
toCommands fn cnt = case prRoot <$> parseScript fileLoader (newParseSpec { psFilename = fn, psScript = cnt }) of
        Identity (Just t)  -> Right $ concatMap extractParams (extractCommands t)
        _ -> Left "failed"
   where
     fileLoader = SystemInterface (\_ -> Identity (Left "can't load"))


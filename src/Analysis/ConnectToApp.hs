{-# LANGUAGE TupleSections #-}

module Analysis.ConnectToApp where

-- module Analysis.ConnectToApp (buildNetApps) where

import Analysis.Fiche
import Analysis.Types.Network
import Control.Lens
import Data.Either (partitionEithers)
import Data.List (foldl')
import qualified Data.Map.Strict as M
import Data.Maybe (fromMaybe)
import qualified Data.Set as S
import Data.Text (Text)
import qualified Data.Text as T
import Data.Textual (toText)
import Network.IP.Addr

data PT = PTCP | PUDP
  deriving (Show, Eq, Ord)

protoToText :: PT -> Text
protoToText pt = case pt of
  PTCP -> "TCP"
  PUDP -> "UDP"

data CLT = CLT PT (IP, InetPort) (IP, InetPort)
  deriving (Show, Eq, Ord)

data SRV = SRV PT IP InetPort
  deriving (Show, Eq, Ord)

buildNetApps :: [NetIf] -> [Connection] -> [FicheApplication]
buildNetApps netifaces cnxs = map (mkfiche ifaces) (itoList perPrograms)
  where
    ifaces = toListOf (folded . to mkIP) netifaces
    mkIP i = case i of
      If4 _ ip _ -> IPv4 $ netHost ip
      If6 _ ip _ -> IPv6 $ netHost ip
    -- on regroupe les connexions par programme
    perPrograms = M.fromListWith (<>) $ do
      cnx <- cnxs
      return (T.takeWhile (`notElem` [':', ' ']) . snd <$> _proginfo cnx, [_ipproto cnx])

mkfiche :: [IP] -> (Maybe Text, [IPProto]) -> FicheApplication
mkfiche ifaces (mappname, connections) = FicheApplication name [] (map mkServer $ M.toList serversPerPorts) (map mkClient $ M.toList clientsPerPorts)
  where
    (listen, established) = partitionListen connections
    (serverMap, remoteClients) = partitionServerClients ifaces listen established
    name = fromMaybe "??" mappname
    serversPerPorts = M.fromListWith (<>) $ do
      ((pt, lip, port), clts) <- M.toList serverMap
      return (port, ([(pt, lip)], clts))
    clientsPerPorts = M.fromListWith (<>) $ do
      CLT pr _ (rip, rport) <- remoteClients
      return (rport, [(pr, rip)])

-- | fait une fiche serveur
mkServer :: (InetPort, ([(PT, IP)], [CLT])) -> AppServer
mkServer (port, (protoips, clients)) = AppServer (map ipProtoText $ snub protoips) (unInetPort port) False (map mkClient' $ snub clients)
  where
    mkClient' :: CLT -> Text
    mkClient' (CLT proto _ (rip, rport)) = protoToText proto <> "/" <> toText rip <> ":" <> toText rport

ipProtoText :: (PT, IP) -> Text
ipProtoText (proto, ip) = protoToText proto <> "/" <> toText ip

-- | fait une fiche client
mkClient :: (InetPort, [(PT, IP)]) -> AppClient
mkClient (port, dests) = AppClient (map ipProtoText $ snub dests) (unInetPort port)

-- | trie les connexions entre les écoutes et les établies
partitionListen :: [IPProto] -> ([SRV], [CLT])
partitionListen connections = partitionEithers $ do
  proto <- connections
  let l4 = case proto of
        TCP lip lport rip stt -> ex PTCP lip lport rip stt
        UDP lip lport rip stt -> ex PUDP lip lport rip stt
      ex pr lip lport rip stt = case stt ^? remPort of
        Just rp -> Right (CLT pr (lip, lport) (rip, rp))
        Nothing -> Left (SRV pr lip lport)
  return l4

-- | trie les connexions entre celles qui sont à destination d'un des serveurs et les autres,
-- et les range pour ce serveur
partitionServerClients :: [IP] -> [SRV] -> [CLT] -> (M.Map (PT, IP, InetPort) [CLT], [CLT])
partitionServerClients ifaces listen = foldl' sortClient (serverMap, [])
  where
    serverMap :: M.Map (PT, IP, InetPort) [CLT]
    serverMap = M.fromList $ map (,[]) $ do
      SRV pr lip lport <- listen
      if lip `elem` [IPv4 anyIP4, IPv6 anyIP6]
        then [(pr, ip, lport) | ip <- ifaces]
        else [(pr, lip, lport)]
    sortClient (mp, remotes) f@(CLT pt (lip, lport) _) =
      let key = (pt, lip, lport)
       in case M.lookup key mp of
            Nothing -> (mp, f : remotes)
            Just lst -> (M.insert key (f : lst) mp, remotes)

snub :: Ord a => [a] -> [a]
snub = S.toList . S.fromList

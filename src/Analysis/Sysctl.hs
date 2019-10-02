{-# LANGUAGE OverloadedStrings #-}
module Analysis.Sysctl (anaSysctl, wrongSysctl) where


import           Analysis.Common
import           Analysis.Types

import           Control.Monad
import           Data.Maybe
import           Data.Sequence   (Seq)
import qualified Data.Sequence   as Seq
import           Data.Text       (Text)
import qualified Data.Text       as T

anaSysctl :: Analyzer (Seq ConfigInfo)
anaSysctl = lineAnalyzer "conf/sysctl-a.txt" (chk . map T.strip . T.splitOn "=")
    where
        chk [k,v] = Right (Sysctl k v)
        chk x     = Left ("Could not parse " <> show x)

checks :: [ (Pattern Text, Text, Severity, Maybe Text) ]
checks = [ (S ".arp_accept"          , "0", Low   , Just "Gratuitous ARP should not be accepted.")
         , (S ".accept_source_route" , "0", Low   , Just "Source routing should not be accepted.")
         , (S ".forwarding"          , "0", Medium, Just "IP forwarding should be disabled.")
         , (S ".accept_redirects"    , "0", Low   , Just "Do not accept ICMP redirects.")
         , (S ".secure_redirects"    , "0", Low   , Just "Do not accept secure ICMP redirects.")
         , (S ".rp_filter"           , "1", Low   , Just "Source validation by reversed path should be enabled (RFC 1812).")
         , (S ".send_redirects"      , "0", Low   , Just "Do not send redirects.")
         , (S ".router_solicitations", "0", Low   , Just "The number of router solicitations to send beforer assuming no routers are present should be 0.")
         , (S ".accept_ra_rtr_pref"  , "0", Low   , Nothing)
         , (S ".accept_ra_pinfo"     , "0", Low   , Nothing)
         , (S ".accept_ra_defrtr"    , "0", Low   , Nothing)
         , (S ".autoconf"            , "0", Low   , Nothing)
         , (S ".dad_transmits"       , "0", Low   , Nothing)
         , (S ".max_addresses"       , "1", Low   , Nothing)
         , (E "net.ipv4.ip_forward"  , "0", Medium, Just "IP forwarding should be disabled.")
         , (E "net.ipv4.tcp_syncookies",              "1", Medium, Nothing)
         , (E "net.ipv4.icmp_echo_ignore_broadcasts", "1", Low   , Nothing)
         , (E "net.ipv4.tcp_timestamps"             , "0", Low   , Nothing)
         , (E "fs.protected_hardlinks"              , "1", Medium, Nothing)
         , (E "fs.protected_symlinks"               , "1", Low   , Nothing)
         , (E "kernel.exec-shield"                  , "1", Medium, Nothing)
         , (E "kernel.randomize_va_space"           , "2", Medium, Nothing)
         , (E "kernel.kptr_restrict"                , "1", Medium, Nothing)
         , (E "kernel.dmesg_restrict"               , "2", Medium, Nothing)
         ]

wrongSysctl :: [(Text, Text)] -> Seq Vulnerability
wrongSysctl = Seq.fromList . mapMaybe (uncurry checkSysctl)

checkSysctl :: Text -> Text -> Maybe Vulnerability
checkSysctl key value = either Just (const Nothing) (mapM_ checkSysctl' checks)
    where
        checkSysctl' (pattern, expected, severity, desc) = when (match pattern key && value /= expected)
                                                                (Left (Vulnerability severity (WrongSysctl key value expected desc)))


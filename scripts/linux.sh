#!/bin/bash
export LANG=C
export LC_TIME=C
export LC_ALL=C

USAGE="Usage: $0 [-hn] [extra-path1 ... extra-pathN]
       -h : print this message
       -f : force run even if not on Linux (DANGEROUS)
       -n : no-find, do not traverse the entire filesystem to produce fs/find.txt
       -a : audit mode, retrieves secrets and extra data
       extra-path[1..N] : specify extra paths that will be copied in the 'more' folder,
          e.g. /opt/custom-server/conf\\n"
# Default options values
OPT_NOFIND=false
OPT_AUDIT=false

# Command line options parsing
while getopts hnaf OPT; do
  case "$OPT" in
    h) # help
      echo -e "$USAGE" >&2
      exit 0
      ;;
    n) # nofind
      OPT_NOFIND=true
      ;;
    f) # force
      OPT_FORCE=true
      ;;
    a) # audit mod
      OPT_AUDIT=true
      ;;
    \?) # getopts issues an error message
      echo -e "$USAGE" >&2
      exit 1
      ;;
  esac
done

# Check we're running Linux
if [ "x$OPT_FORCE" != "xtrue" ] && [ "$(uname)" != "Linux" ]; then
	echo "Not running on Linux, exiting"
	exit 1
fi

# Only set tracing after option parsing
set -x

#-----------
hostname=$(hostname)
mkdir "$hostname"

( cd "$hostname" || exit

# setup stderr logging
mkfifo script.fifo
tee script.log < script.fifo &
teepid=$!
exec > script.fifo 2>&1

#-----------
shopt -s expand_aliases
alias safe_find="find / -fstype nfs -prune \
   -o -path '/proc' -prune \
   -o -path '/sys' -prune \
   -o"
if [ "x$OPT_NOFIND" == "xtrue" ] || [ "x$OPT_AUDIT" == "xfalse" ] ; then
  echo "nofind"
else
  mkdir fs
  safe_find -printf '%i %n %A++%AZ %T++%TZ %C++%CZ %U %G %k %y %#m %s %p -> %l\n' > fs/find-ng.txt
fi

#-----------
( mkdir conf
  cd conf || exit
  sysctl -a > sysctl-a.txt
  mount -v > mount-v.txt
  uname -a > uname-a.txt
  lsb_release -a > lsb_release-a.txt
  initctl list > initctl-list.txt
  getent passwd > passwd
  getent group > group
  for usr_lib_file in fedora_release redhat_release issue.net
  do
    [ -f "/usr/lib/$usr_lib_file" ] && cp "/usr/lib/$usr_lib_file" .
  done
  if [ "x$OPT_AUDIT" == "xtrue" ]; then
    tar --atime-preserve -czf etc.tar.gz /etc
    getent shadow > shadow
  else
    tar --atime-preserve -czf etc.tar.gz /etc/passwd /etc/sudoers /etc/group /etc/shells /etc/cron* /etc/debian_version /etc/*-release /etc/hosts.equiv /etc/hostname /etc/HOSTNAME /etc/sysconfig/network
  fi
  )

#-----------
if [ "x$OPT_AUDIT" == "xtrue" ]; then
( mkdir log
  cd log || exit
  tar --atime-preserve -czf auth.tar.gz /var/log/auth.log*
  tar --atime-preserve -czf wtmp.tar.gz /var/log/wtmp*
  tar --atime-preserve -czf btmp.tar.gz /var/log/btmp*
  tar --atime-preserve -czf lastlog.tar.gz /var/log/lastlog*
  )
fi

#-----------
( mkdir reseau
  cd reseau || exit
  ip addr list > ip-addr.txt
  ip neighbor > ip-neighbor.txt
  ip route show > ip-routes.txt
  ip -6 route show >> ip-routes.txt
  ss -laputen > ss-laputen.txt

  arp -n > arp-n.txt
  ifconfig -a > ifconfig-a.txt
  netstat -nap > netstat-nap.txt
  netstat -nteupal > netstat-teupaln.txt
  netstat -nar > netstat-nar.txt
  lsof -i > lsof-i.txt
  route -n > route-n.txt
  route -6n > route-6n.txt
  )

#-----------
if [ "x$OPT_AUDIT" == "xtrue" ]; then
( mkdir firewall
  cd firewall || exit
  iptables-save > iptables-save.txt
  iptables -L -n -v > iptables-Lnv.txt
  iptables -t nat -L -n -v > iptables-nat-Lnv.txt
  ip6tables-save > ip6tables-save.txt
  ip6tables -L -n -v > ip6tables-Lnv.txt
  ip6tables -t nat -L -n -v > ip6tables-nat-Lnv.txt
  )
fi

#-----------
( mkdir etat
  cd etat || exit
  date > date.txt
  lsof > lsof.txt
  lsof -v > lsof-v.txt
  dmesg > dmesg.txt
  ps aguxwww > ps-aguxwww.txt
  last -a > last-a.txt
  lastlog > lastlog.txt
  df -ah > df-ah.txt
  uptime > uptime.txt
  free -m > free-m.txt
  swapon -s > swapon-s.txt
  cat /proc/loadavg > loadavg.txt
  cat /proc/version > version.txt
  cat /proc/modules > modules.txt
  ipcs > ipcs.txt
  echo "$hostname" > hostname
  )

#-----------
( mkdir logiciels
  cd logiciels || exit
  dpkg -l > dpkg-l.txt
  cp /var/lib/dpkg/status dpkg-status
  cp /var/log/dpkg.log* .
  rpm -qa > rpm-qa.txt
  rpm -qa --last > rpm-qa-last.txt
  yum list updates > yum-list-updates.txt
  cp /etc/sysconfig/rhn/systemid .
  ls -d /var/db/pkg/*/* > gentoo-packages.txt
  )

#-----------
( mkdir hardware
  cd hardware || exit
  cat /proc/meminfo > meminfo.txt
  cat /proc/cpuinfo > cpuinfo.txt
  lspci -v > lspci-v.txt
  )

users=$(getent passwd | cut -d ":" -f 1)

#-----------
( mkdir crontab
  cd crontab || exit
  for user in $users; do
    echo "$user:" && crontab -l -u "$user" 2>&1 | tee "$user-crontab"
  done
  )

#-----------
if [ "x$OPT_AUDIT" == "xtrue" ]; then
( mkdir conf_user
  cd conf_user || exit
  files=".bash* .profile .ksh* .zshrc .tcshrc .rhosts .netrc .ssh/ .x* .history .k5*"
  for user in $users; do
          file="$user-conf.tar"
          home=$(getent passwd | grep "^$user:" | cut -d ':' -f 6);
          echo "$user : $home" ;
    prev=$PWD
    cd "$home" || exit
    importantfiles=$(ls "$files" 2>/dev/null)
    if [ -n "$importantfiles" ] ; then
      tar --atime-preserve -cvf "$prev/$file" "$files"
    fi
    cd "$prev" || exit
  done
  )
fi

#-----------
if [ "x$OPT_AUDIT" == "xtrue" ]; then
( mkdir rpc
  cd rpc || exit
  rpcinfo -p > rpcinfo-p.txt
  showmount  > showmount.txt
)
fi

#-----------
# save additionnal paths, given in argv (ex : "./linux.sh /opt/custom_server/conf/")
( mkdir more
  for morepath in "$@"; do
    cp -r --parent "$morepath" more/
  done
  )

# ---------
# close fds, wait for tee to finish, remove the fifo
exec 1>&- 2>&-
wait $teepid
rm -f script.fifo

#-----------
cd ..

tar --atime-preserve -czf "$hostname.tar.gz" "$hostname"
rm -rf "$hostname"
)

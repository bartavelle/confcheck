#!/bin/bash -x
hostname=$(hostname)
mkdir $hostname
cd $hostname
#-----------
mkdir conf
cd conf
tar -cf etc.tar /etc
gzip etc.tar
sysdef > sysdef.txt
getconf -a > getconf-a.txt
uname -a > uname-a.txt
cd ..
#-----------
mkdir reseau
cd reseau
ifconfig -a > ifconfig-a.txt
netstat -na > netstat-na.txt
netstat -nar > netstat-nar.txt
netstat -nar -f inet6 > netstat-nar-inet6.txt
cd ..
#-----------
mkdir etat
cd etat
date > date.txt
test -x /usr/ucb/ps
if [ $? -eq 0 ]; then
	/usr/ucb/ps wwaux > ps-wwaux.txt
else
	ps -efl > ps-efl.txt
fi
last -a > last-a.txt
df -ak > df-ak.txt
uptime > uptime.txt
cd ..
#-----------
mkdir logiciels
cd logiciels
pkginfo -l > pkginfo-l.txt
pkginfo -i > pkginfo-i.txt
showrev -p > showrev-p.txt
cd ..
#-----------
mkdir hardware
cd hardware
prtconf -v > prtconf-v.txt
cd ..
#-----------
shopt -s expand_aliases
alias safe_find="find / \( -fstype nfs -o -fstype cachefs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune \
	 -o"
if [ "a$1" == "anofind" ] ; then
	echo "nofind"
else
	mkdir fs
	cd fs
	safe_find -type f -perm -o+w -ls | tee world_writable
	safe_find -type d -perm -o+w -ls | tee world_writable_dir
	safe_find -type f \( -perm -4000 -o -perm -2000 \) -ls | tee suid_sgid.txt
	safe_find -ls > find.txt
	cd ..
fi
#-----------
mkdir crontab
cd crontab
users=$(getent passwd | cut -d ":" -f 1)
for user in $users; do 
	echo "$user:" && crontab -l $user 2>&1 | tee "$user-crontab"
done
cd ..
#-----------
mkdir conf_user
cd conf_user
files=".bash* .profile .ksh* .zshrc .tcshrc .rhosts .netrc .ssh/ .x*"
for user in $users; do 
        file="$user-conf.tar"
        home=$(getent passwd | grep "^$user:" | cut -d ':' -f 6);
        echo "$user : $home" ;
	prev=$PWD
	cd $home
	nb=$(ls -1 $files 2>/dev/null | wc -l)
	if [ $nb != '0' ] ; then
		tar -cvf "$prev/$file" $files
	fi
	cd $prev
done
cd ..
#-----------
mkdir rpc
cd rpc
rpcinfo -p > rpcinfo-p.txt
showmount  > showmount.txt
cd ..
cd ..


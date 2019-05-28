# confcheck

## Building

You will need the [stack build tool](https://docs.haskellstack.org/en/stable/install_and_upgrade/).

```
git clone https://github.com/bartavelle/confcheck-types
git clone https://github.com/bartavelle/confcheck-audittool
git clone https://github.com/bartavelle/confcheck
cd confcheck
stack build
```

## Preparing the sources

In the `confcheck` directory,

```
mkdir sources serialized
cd sources
for d in 2002 2003 2004 2005 2006 2007 2008 2009 2010 2011 2012 2013 2014 2015 2016 2017 2018
do
   wget -O- http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-$d.xml.gz  | gunzip > nvdcve-2.0-$d.xml
done
wget -O- http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2 | bunzip2 > com.redhat.rhsa-all.xml

for v in 13.1 13.2 12.2 12.3
do
  wget -O opensuse.$v.xml http://support.novell.com/security/oval/opensuse.$v.xml
done

wget -O suse.linux.enterprise.12.xml http://support.novell.com/security/oval/suse.linux.enterprise.12.xml
wget -O suse.linux.enterprise.server.10.xml http://support.novell.com/security/oval/suse.linux.enterprise.server.10.xml
wget -O suse.linux.enterprise.server.11.xml http://support.novell.com/security/oval/suse.linux.enterprise.server.11.xml
wget -O patchdiag.ref https://getupdates.oracle.com/reports/patchdiag.xref
wget -O com.ubuntu.trusty.cve.oval.xml https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.trusty.cve.oval.xml
wget -O com.ubuntu.xenial.cve.oval.xml https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.xenial.cve.oval.xml

cd ..

.stack-work/install/x86_64-linux/lts-10.6/8.2.2/bin/confcheck-serializer

```

You also need to retrieve Microsoft's `BulletinSearch.xlsx` and convert it to CSV.

## Using the program

```
.stack-work/install/x86_64-linux/lts-10.6/8.2.2/bin/confcheck-exe [cvs] [path to files]
```

## FAQ

### I do not know what this is about!

:(



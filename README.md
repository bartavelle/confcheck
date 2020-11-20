# confcheck

## Building from sources

You will need the [stack build tool](https://docs.haskellstack.org/en/stable/install_and_upgrade/).

```
git clone https://github.com/bartavelle/confcheck-types
git clone https://github.com/bartavelle/confcheck-audittool
git clone https://github.com/bartavelle/confcheck
cd confcheck
mv stack.yaml.sample stack.yaml
mkdir dist
stack install --local-bin-path dist --ghc-options "-j4 +RTS -A128m -n2m -qg -RTS"
```

All executables now reside in the `dist` directory.

## Preparing the sources

From the `confcheck` directory,

```
dist/confcheck-serializer
```

### Updating the sources

Delete files you want to update from the sources directory, then run the serializer again:

```
# updating Ubuntu sources
rm sources/com.ubuntu.*
dist/confcheck-serializer
```

# confcheck-patches

The `confcheck-patches` program displays missing patches. It currently supports the following distributions:

 * RHEL, CentOS
 * OpenSuSE 12.2, 12.3, 13.2
 * OpenSUSE Leap 15.0, 15.1
 * Ubuntu 14.04, 16.04, 18.04, 19.10, 20.04
 * Debian 7, 8, 9, 10

```
Usage: confcheck-patches [--path PATH] 
                         (--sles VERSION | --rh VERSION | --opensuse VERSION | 
                           --leap VERSION | --ubuntu VERSION | --debian VERSION)
                         (--rpm PATH | --dpkgstatus PATH | --dpkg PATH) 
                         [--arch ARCH] [--json] [--severity SEV]
  Get missing patches from packages lists

Available options:
  --path PATH              Path to the oval serialized
                           files (default: "/usr/share/confcheck-cli/serialized")
  --sles VERSION           SuSE Linux Enterprise Server
  --rh VERSION             RedHat Linux
  --opensuse VERSION       OpenSuSE
  --leap VERSION           OpenSUSE Leap
  --ubuntu VERSION         Ubuntu Linux
  --debian VERSION         Debian Linux
  --rpm PATH               Path to the output of rpm -qa
  --dpkgstatus PATH        Path to the copy of /var/lib/dpkg/status
  --dpkg PATH              Path to the output of dpkg -l *WARNING* this will
                           produce an incomplete output!!!
  --arch ARCH              Target architecture (default: "x86_64")
  --json                   JSON output
  --severity SEV           Minimum severity to display ('low', 'med', 'high')
  -h,--help                Show this help text
```

Usually, you will run it in the following way:

```
confcheck-patches --leap 15.1 --rpm output_of_rpm_qa --severity high
```

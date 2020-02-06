# confcheck

## Building

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

## Preparing the sources

From the `confcheck` directory,

```
dist/confcheck-serializer
```

## Using the program

From the `confcheck` directory,

```
dist/confcheck-exe
```

## FAQ

### I do not know what this is about!

:(



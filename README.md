# safe-install

**Install dependencies. Not malware.**

`safe-install` stops malicious npm, pnpm, Yarn and bun install scripts before they run.
It analyzes your whole dependency tree from the lockfile, installs with lifecycle scripts
disabled, shows you every package that wants to run a script, and runs only the ones you
approved. Linux, macOS and Windows; single static binary.

> **Status:** early development. Nothing to install yet.

## How it works

1. **Analyze**: lockfile → full tree → registry metadata → risk score per package
2. **Install**: your package manager, with all lifecycle scripts disabled
3. **Inspect**: list every package that wants a `preinstall`/`install`/`postinstall` script, and flag risky ones
4. **Approve**: per package, pinned to the script's content hash
5. **Run**: only the approved scripts (Linux: optionally under a runtime monitor)

## Supported package managers

npm · pnpm · Yarn classic · Yarn berry · bun

## Build from source

Requires Go 1.25+.

```sh
go build -o bin/safe-install ./cmd/safe-install
./bin/safe-install version
```

## Check without installing

```sh
safe-install check                  # score every package in the lockfile
safe-install check --fail-on medium # exit 1 at medium risk or worse
safe-install check --format json
```

New versions must be at least `--min-age` old (default `72h`; `0` disables). `install`
passes this to the package manager so fresh releases are not picked up, and `check`
flags any already in the lockfile.

## Privacy

No telemetry. `safe-install` only talks to your configured package registry and, for
advisories, the OSV API.

## Security

Found a bypass? Please report it privately, see [SECURITY.md](SECURITY.md).

## Acknowledgements

The release-age gate is inspired by [safe-npm](https://github.com/kevinslin/safe-npm).

## License

[Apache-2.0](LICENSE)

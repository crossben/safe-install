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

## Install

```sh
safe-install                 # or: safe-install install
safe-install install --yes   # approve every script below high risk
safe-install install -- --omit=dev   # flags after -- go to the package manager
```

Dependencies are installed with every lifecycle script disabled. safe-install then lists
the packages that want to run `preinstall` / `install` / `postinstall` scripts, flags
risky ones (download-and-execute, `eval` / encoded blobs, credential access, plus the
registry checks below), and runs only the ones you approve, dependencies first. Without a
terminal (CI) nothing is approved; `--ci` also exits 1 when a high-risk script is present.
Your project's own lifecycle scripts are never run for you.

Running approved scripts uses `npm run` inside each package's directory, so npm must be
on `PATH` (it ships with Node).

## Approvals and policy

Answering **y** at the prompt (or running `safe-install approve <pkg>`) records the approval
in `.safe-install.json`. Commit it so your team shares approvals:

```json
{
  "minReleaseAge": "3d",
  "minReleaseAgeExclude": ["typescript", "@types/*"],
  "failOn": "high",
  "allowScripts": {
    "esbuild": { "version": "0.25.10", "hash": "sha256-…", "at": "2026-10-03" }
  }
}
```

An approval is pinned to a hash of the scripts **and the files they run**: if either
changes, safe-install reports `SI-SCR-005` and asks again. Approved scripts run without a
prompt, also in CI. A user-wide file with the same format lives in your config directory
(`approve --global`); the project file wins on conflicts, and flags win over both.

```sh
safe-install scripts              # packages with install scripts and their approval state
safe-install approve esbuild      # approve and run now (--revoke, --global, --no-run)
safe-install add left-pad         # add packages through the same review
safe-install explain SI-SCR-002   # what a rule means and what to do
```

`minReleaseAgeExclude` exempts packages from the release-age findings. The age passed to
the package manager itself applies to every package.

### Use it every time (opt-in)

`safe-install shell-init <bash|zsh|fish|pwsh>` prints functions that send `npm install`,
`pnpm add`, `yarn`, `bun i` and friends through safe-install. It changes nothing on its own:

```sh
eval "$(safe-install shell-init bash)"   # add to ~/.bashrc or ~/.zshrc
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

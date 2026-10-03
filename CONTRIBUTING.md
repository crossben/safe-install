# Contributing

Thanks for helping! Small, focused pull requests are easiest to review.

## Setup

Requires Go 1.25+.

```sh
make test   # go test ./...
make lint   # golangci-lint run
make build  # bin/safe-install
```

## Ground rules

- **Dependencies:** this is a supply-chain security tool. Every new dependency needs a
  reason in the PR description.
- **Tests:** new rules and lockfile parsers come with fixtures (golden files).
- **Malicious samples:** never commit real malware. Test packages must be harmless
  imitations.
- **Security issues:** see [SECURITY.md](SECURITY.md), not the issue tracker.

By contributing you agree your work is licensed under Apache-2.0.
Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

.PHONY: build test lint vuln snapshot clean

build:
	go build -trimpath -o bin/safe-install ./cmd/safe-install

test:
	go test -race ./...

lint:
	golangci-lint run

vuln:
	govulncheck ./...

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist

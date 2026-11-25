BINARY  := coffer
VERSION := 1.0.0
LDFLAGS := -s -w

.PHONY: build test race dev clean docker cross

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/coffer

test:
	go vet ./...
	go test -count=1 ./...

race:
	go test -race -count=1 ./...

dev: build
	./bin/$(BINARY) server -dev -dev.root-token=root -dir=./coffer-dev

cross:
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 ./cmd/coffer
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-arm64 ./cmd/coffer
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-darwin-arm64 ./cmd/coffer
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-windows-amd64.exe ./cmd/coffer

docker:
	docker build -t coffer:$(VERSION) .

clean:
	rm -rf bin coffer-dev

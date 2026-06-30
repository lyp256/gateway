
generate:
	go generate ./...

build-debug: generate
	go build "-gcflags=all=-N -l" -o bin/gateway  $(shell go list)/cmd

build: generate
	go build -o bin/gateway  $(shell go list)/cmd
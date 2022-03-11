.DEFAULT_GOAL := help

APPLICATION?=cert-test-go
COMMIT_SHA?=$(shell git rev-parse --short HEAD)
DOCKER?=docker
REGISTRY?=jonascheng
# is Windows_NT on XP, 2000, 7, Vista, 10...
ifeq ($(OS),Windows_NT)
GOOS?=windows
RACE=""
else
GOOS?=$(shell uname -s | awk '{print tolower($0)}')
GORACE="-race"
endif

.PHONY: setup
setup: ## setup go modules
	go mod tidy

.PHONY: clean
clean: ## cleans the binary
	go clean
	rm -rf ./bin
	rm -rf *.key *.crt

.PHONY: run
run: setup server-key ## runs go run the application
	go run ${GORACE} cmd/${APPLICATION}/main.go

.PHONY: test
test: build server-key ## runs tests
	./bin/${APPLICATION}

.PHONY: build
build: clean ## build the server application
	GOOS=${GOOS} GOARCH=amd64 go build ${GORACE} -a -v -ldflags="-w -s" -o bin/${APPLICATION} cmd/${APPLICATION}/main.go

.PHONY: server-key
server-key:
	## Key considerations for algorithm RSA ≥ 1024-bit
	## PKCS1 format (nocrypt)
	if [ ! -f pkcs1-nocrypt.key ]; then openssl genrsa -out pkcs1-nocrypt.key 1024; fi;
	## Generation of self-signed(x509) public key (PEM-encodings .pem|.crt) based on the private (.key)
	if [ ! -f pkcs1-nocrypt.crt ]; then openssl req -new -x509 -key pkcs1-nocrypt.key -out pkcs1-nocrypt.crt -days 3650 -subj "/C=TW/ST=Test/L=Test/O=Test/OU=Test/CN=localhost/emailAddress=Test@email"; fi;
	## PKCS8 format (nocrypt)
	if [ ! -f pkcs8-nocrypt.key ]; then openssl pkcs8 -topk8 -inform PEM -in pkcs1-nocrypt.key -nocrypt -out pkcs8-nocrypt.key; fi;
	## Generation of self-signed(x509) public key (PEM-encodings .pem|.crt) based on the private (.key)
	if [ ! -f pkcs8-nocrypt.crt ]; then openssl req -new -x509 -key pkcs8-nocrypt.key -out pkcs8-nocrypt.crt -days 3650 -subj "/C=TW/ST=Test/L=Test/O=Test/OU=Test/CN=localhost/emailAddress=Test@email"; fi;
	@echo "********** Please type pass phrase 'mypassword' **********"
	## PKCS1 format (crypt)
	if [ ! -f pkcs1-crypt.key ]; then openssl genrsa -des3 -out pkcs1-crypt.key 1024; fi;
	## Generation of self-signed(x509) public key (PEM-encodings .pem|.crt) based on the private (.key)
	if [ ! -f pkcs1-crypt.crt ]; then openssl req -new -x509 -key pkcs1-crypt.key -out pkcs1-crypt.crt -days 3650 -subj "/C=TW/ST=Test/L=Test/O=Test/OU=Test/CN=localhost/emailAddress=Test@email"; fi;
	## PKCS8 format (crypt)
	if [ ! -f pkcs8-crypt.key ]; then openssl pkcs8 -topk8 -inform PEM -in pkcs1-nocrypt.key -out pkcs8-crypt.key; fi;
	## Generation of self-signed(x509) public key (PEM-encodings .pem|.crt) based on the private (.key)
	if [ ! -f pkcs8-crypt.crt ]; then openssl req -new -x509 -key pkcs8-crypt.key -out pkcs8-crypt.crt -days 3650 -subj "/C=TW/ST=Test/L=Test/O=Test/OU=Test/CN=localhost/emailAddress=Test@email"; fi;

.PHONY: help
help: ## prints this help message
	@echo "Usage: \n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

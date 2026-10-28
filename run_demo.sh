#!/usr/bin/env bash
set -e

if [ ! -f "certs/server.crt" ]; then
    ./certs/generate_certs.sh
fi

go build -o bin/server server/main.go
o build -o bin/client client/main.go

go test -v ./...

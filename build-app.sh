#!/bin/bash
echo ""
echo "run: go get -u -v file.go"
echo "run: go build -v file.go"
docker run -it --rm -v "$PWD":/usr/src/go-server -w /usr/src/go-server golang /bin/bash

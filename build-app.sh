#!/bin/bash
echo ""
echo "run: go get -d -v"
echo "run: go build -v"
docker run -it --rm -v "$PWD":/usr/src/go-server -w /usr/src/go-server golang /bin/bash

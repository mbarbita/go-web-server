#!/bin/bash
docker run --rm -v "$PWD":/usr/src/go-app -w /usr/src/go-app golang go build -v

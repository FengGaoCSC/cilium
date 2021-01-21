#!/bin/bash

IMAGE="go-mod-wrapper"

docker build --tag $IMAGE $(dirname $(readlink -ne $BASH_SOURCE))
docker container run \
	--user "$(id -u):$(id -g)" \
	--volume $(pwd)/:/go/src/github.com/cilium/cilium \
	--workdir /go/src/github.com/cilium/cilium \
	--tty \
	--interactive \
	$IMAGE \
	"$@"

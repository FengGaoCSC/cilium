#!/bin/bash

#export DOCKER_BUILDKIT=1
export DOCKER_BUILDX=1

export DOCKER_REGISTRY=docker.io
export DOCKER_DEV_ACCOUNT=gaofeng1973

#make docker-images-all 
make docker-cilium-image

#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases
hubble_version="v0.11.5-cee.1"

declare -A hubble_sha256
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.11.5-cee.1
hubble_sha256[amd64]="f945841eb9c92922f558c8c1b60eae084fa9efd7d28bfaf0878a1359dd24e5c3"
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.11.5-cee.1
hubble_sha256[arm64]="58bacf3e9764d53c66fae63378b0bab85b035f97e7b71219f332f07cdfc9e5d8"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/isovalent/hubble-releases/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble

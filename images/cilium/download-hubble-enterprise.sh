#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases
hubble_version="v0.12.2-cee.1"

declare -A hubble_sha256
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.12.2-cee.1
hubble_sha256[amd64]="53b62e82b94e9a8adfd307cfeb3755c777ac578ca41f147c15d7d5997abe91fa"
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.12.2-cee.1
hubble_sha256[arm64]="f713c4a7ff5f005c9feaf19bc90ddf7d68a39c320b2b80e5a6266c722ee731e2"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/isovalent/hubble-releases/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble

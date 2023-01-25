#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases
hubble_version="v0.11.4-cee.1"

declare -A hubble_sha256
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.11.4-cee.1
hubble_sha256[amd64]="523a1a67f38eeb6a3392168e5cd55fbec4716f70895257be76f82720be49db17"
# renovate: datasource=github-release-attachments depName=isovalent/hubble-releases digestVersion=v0.11.4-cee.1
hubble_sha256[arm64]="83495e18493ce1690279c6d3c511f7e61889f0987dcfa7056516f86fe605a483"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/isovalent/hubble-releases/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble

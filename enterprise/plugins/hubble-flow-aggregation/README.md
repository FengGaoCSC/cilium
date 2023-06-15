# hubble-flow-aggregation

Plugin providing the aggregation functionality to Atlantis.

## Structure

This is an outline for how this plugin is structured and perhaps a tempate for
other to follow as well.

```
❯ tree -L 1 .
├── atlantis.yaml       // atlantis configuration file consisting only of this plugin
├── cilium-vX.Y.Z       // cilium source (OSS from github)
├── cilium-gen          // `cilium` folder, but after `atlantis gen` run
├── proto               // separate package which handles proto mutation for this plugin
```

### Why isn't `cilium-*` checked in?

Both `cilium-vX.Y.Z` and `cilium-gen` are gigantic folders. They are the entire
cilium repository, which is quite sizeable. Besides, due to the `go mod
vendor`, all the relevant go code is already checked into the repository.

### Automating the structure

Tooling for creating `cilium-*` folders should be straight forward to make, as
it just has to go fetch the specified cilium version (perhaps driven by
`go.mod`) and run the Atlantis binary with the configuration file.

### `go mod tidy` fails, what's up with that?

```
❯ go mod tidy
go: github.com/cilium/cilium@v1.9.4 (replaced by ./cilium-gen): reading cilium-gen/go.mod: no such file or directory
```

Since the `cilium-*` directory is a git submodule, it first needs to be initialized for any `go mod` commands to work.

Example:
```
git submodule update --init --recursive
cd ./cilium-gen
atlantis gen --config ../atlantis.yaml
```

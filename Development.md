# e3db-go
Software Development Kit (SDK) for interacting with Tozny products and services from go software environments AND a Command Line Interface for shell environments.

# Development


## Build

```bash
make build
```

## Lint

Lint go source control and dependencies

```bash
make lint
```

# Publishing

## Versioning

Follow [semantic versioning](https://semver.org) when releasing new versions of this library.

Releasing involves tagging a commit in this repository, and pushing the tag. Tagging and releasing of new versions should only be done from the master branch after an approved Pull Request has been merged, or on the branch of an approved Pull Request.

To publish a new version, run

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

or

```bash
make version version=X.Y.Z
```

To consume published updates from other repositories that depends on this module run

```bash
go get github.com/tozny/e3db-go@vX.Y.Z
```

and the go `get` tool will fetch the published artifact and update that modules `go.mod` and`go.sum` files with the updated dependency.

## Platform CLI binaries

CLI binaries for the common platforms (windows, macOS, linux) are built as part of the [build pipeline job](./.travis.yml) that runs when ever a PR is merged to the master branch.


Distribution of binaries is out of band (adding to source repository and hosting in public s3 buckets).

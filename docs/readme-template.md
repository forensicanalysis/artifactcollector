<h1 align="center">{{.Name}}</h1>

<p  align="center">
 <a href="https://{{.ModulePath}}/actions"><img src="https://{{.ModulePath}}/workflows/CI/badge.svg" alt="build" /></a>
 <a href="https://codecov.io/gh/{{.RelModulePath}}"><img src="https://codecov.io/gh/{{.RelModulePath}}/branch/master/graph/badge.svg" alt="coverage" /></a>
 <a href="https://goreportcard.com/report/{{.ModulePath}}"><img src="https://goreportcard.com/badge/{{.ModulePath}}" alt="report" /></a>
 <a href="https://pkg.go.dev/{{.ModulePath}}"><img src="https://img.shields.io/badge/go.dev-documentation-007d9c?logo=go&logoColor=white" alt="doc" /></a>
</p>

{{.Doc}}
### Installation

Download from https://github.com/forensicanalysis/artifactcollector/releases or

```bash
git clone https://github.com/forensicanalysis/artifactcollector
cd artifactcollector
go install .
```

### Build your own artifactcollector

1. Clone the repository: `git clone https://github.com/forensicanalysis/artifactcollector`.
2. Run `go generate` to download all artifacts.
3. Add artifact definition yaml files as needed in `pack/artifacts`. Do not edit the
artifact definitions, as they will be overwritten.
4. Edit `pack/ac.yaml` and add the artifacts you want to collect.
5. Run `go generate`. This might yield some errors or problems in your artifacts.
6. On windows you can move the syso into the root folder (e.g. `cp resources\artifactcollector.syso .`)
to enable the icon for the executable and the UAC popup.
7. Run `go build .` to generates an executable.

### Embed binaries

Binaries can be added to `pack/bin` and than included into the artifactcollector
in the `go generate` step. Additionally a corresponding COMMAND artifact like
the following is required.

```yaml
name: Autoruns
sources:
- type: COMMAND
  attributes:
    cmd: autorunsc.exe
    args: ["-x"]
supported_os: [Windows]
```

Currently the output to stdout and stderr is saved, but generated
files are not collected.

### Cross compilation

Cross compilation is a bit more difficult, as a cross compiler like MinGW is required by CGO.

Example cross compilation for Windows:

```sh
CGO_ENABLED=1 CC=i686-w64-mingw32-gcc GOOS=windows GOARCH=386 go build .
CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build .
```

{{if .Examples}}
### Usage
{{ range $key, $value := .Examples }}

{{if $key}}### {{ $key }}{{end}}
```go
{{ $value }}
```
{{end}}{{end}}
## Contact

For feedback, questions and discussions you can use the [Open Source DFIR Slack](https://github.com/open-source-dfir/slack).

## Acknowledgment

The development of this software was partially sponsored by Siemens CERT, but
is not an official Siemens product.

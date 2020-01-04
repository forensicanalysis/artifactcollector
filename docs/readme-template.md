<h1 align="center">{{.Name}}</h1>

<p  align="center">
 <a href="https://{{.ModulePath}}/actions"><img src="https://{{.ModulePath}}/workflows/CI/badge.svg" alt="build" /></a>
 <a href="https://codecov.io/gh/{{.RelModulePath}}"><img src="https://codecov.io/gh/{{.RelModulePath}}/branch/master/graph/badge.svg" alt="coverage" /></a>
 <a href="https://goreportcard.com/report/{{.ModulePath}}"><img src="https://goreportcard.com/badge/{{.ModulePath}}" alt="report" /></a>
 <a href="https://pkg.go.dev/{{.ModulePath}}"><img src="https://godoc.org/{{.ModulePath}}?status.svg" alt="doc" /></a>
</p>

{{.Doc}}

### Installation

Download from https://github.com/cugu/artifactcollector/releases or

```bash
go get -u {{.ModulePath}}
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

For feedback, questions and discussions you can use the [Open Source DFIR Slack](https://github.com/open-source-dfir/slack). [How to get an invite](https://github.com/google/timesketch/blob/master/docs/Community-Guide.md).

## Acknowledgment

The development of this software was partially sponsored by Siemens CERT, but
is not an official Siemens product.

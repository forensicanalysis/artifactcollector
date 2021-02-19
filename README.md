<h1 align="center">artifactcollector</h1>

<p  align="center">
 <a href="https://godocs.io/github.com/forensicanalysis/artifactcollector"><img src="https://godocs.io/github.com/forensicanalysis/artifactcollector?status.svg" alt="doc" /></a>
</p>


The artifactcollector project provides a software that collects forensic artifacts
on systems. These artifacts can be used in forensic investigations to understand
attacker behavior on compromised computers.

## Features
The artifactcollector offers the following features

- ️🖥️ Runs on 🖼️ Windows, 🐧 Linux and 🍏 macOS
- 🛍️ Can extract files, directories, registry entries, command and WMI output
- ⭐ Uses the configurable and extensible [Forensics Artifacts](https://github.com/forensicanalysis/artifacts)
- 💾 Creates a forensicstore as [structured output](https://github.com/forensicanalysis/forensicstore)
- 🕊️ It's open source
- 🆓 Free for everyone (including commercial use)

### Installation

Download from https://github.com/forensicanalysis/artifactcollector/releases or

```bash
git clone https://github.com/forensicanalysis/artifactcollector
cd artifactcollector
go install .
```

### Get artifacts & process forensicstores

If you want to extract the raw artifacts or process the collected data have a look at

### [🕵️ elementary](https://github.com/forensicanalysis/elementary)

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

## Limitations

- Currently only files that are smaller than 1GB when compressed can be collected. This can be circumvented by [using a zip archive](https://github.com/forensicanalysis/custom-collector#zip-collector) for artifact collection.

## Contact

For feedback, questions and discussions you can use the [Open Source DFIR Slack](https://github.com/open-source-dfir/slack).

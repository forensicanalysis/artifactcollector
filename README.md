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
  - Supports Windows 2000 and Windows XP
- 🛍️ Can extract files, directories, registry entries, command and WMI output
- ⭐ Uses the configurable and extensible [Forensics Artifacts](https://github.com/forensicanalysis/artifacts)
- 🕊️ Open source

### Installation

Download the latest release for your operating system
from https://github.com/forensicanalysis/artifactcollector/releases

### Usage

On Windows, you can run the artifactcollector by double-clicking the executable.
You may need to confirm the UAC prompt.

On Linux and macOS, you can run the artifactcollector from the terminal: `./artifactcollector`.

### Build your own artifactcollector

1. Clone the repository: `git clone https://github.com/forensicanalysis/artifactcollector`.
2. Add artifact definition yaml files as needed in `config/artifacts`. Do not edit the
   artifact definitions, as they will be overwritten.
3. Edit `config/ac.yaml` and add the artifacts you want to collect.
4. On windows, you can move the syso into the root folder (e.g. `cp resources\artifactcollector.syso .`)
   to enable the icon for the executable and the UAC popup.
5. Run `make build` to generate the artifactcollector binary.

### Embed binaries

Binaries can be added to `config/bin` and then included into the artifactcollector
in the `make build` step. Additionally, a corresponding COMMAND artifact like
the following is required.

```yaml
name: Autoruns
sources:
  - type: COMMAND
    attributes:
      cmd: autorunsc.exe
      args: [ "-x" ]
supported_os: [ Windows ]
```

The command output to stdout and stderr is saved, but generated
files are not collected.

## Contact

For feedback, questions and discussions you can use
the [Open Source DFIR Slack](https://github.com/open-source-dfir/slack).

## License

Most of the artifactcollector is licensed under the MIT License. See [MIT license](LICENSE) for the full license text.

The directories [store/aczip](store/aczip) and [build/go](build/go) contain code from the Go standard library
which is licensed under the [BSD-3-Clause license](LICENSE-BSD).
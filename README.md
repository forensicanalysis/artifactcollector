<h1 align="center">artifactcollector</h1>

<p  align="center">
 <a href="https://github.com/forensicanalysis/artifactcollector/actions"><img src="https://github.com/forensicanalysis/artifactcollector/workflows/CI/badge.svg" alt="build" /></a>
 <a href="https://codecov.io/gh/forensicanalysis/artifactcollector"><img src="https://codecov.io/gh/forensicanalysis/artifactcollector/branch/master/graph/badge.svg" alt="coverage" /></a>
 <a href="https://goreportcard.com/report/github.com/forensicanalysis/artifactcollector"><img src="https://goreportcard.com/badge/github.com/forensicanalysis/artifactcollector" alt="report" /></a>
 <a href="https://pkg.go.dev/github.com/forensicanalysis/artifactcollector"><img src="https://godoc.org/github.com/forensicanalysis/artifactcollector?status.svg" alt="doc" /></a>
</p>


The artifactcollector project provides a software that collects forensic artifacts
on systems. These artifacts can be used in forensic investigations to understand
attacker behavior on compromised computers.

## Features
The artifactcollector offers the following features

- ️🖥️ Runs on 🖼️ Windows, 🐧 Linux and 🍏 macOS
- 🛍️ Can extract files, directories, registry entries, command and WMI output.
- ⭐ Uses the configurable and extensible [Forensics Artifacts](https://github.com/forensicanalysis/artifacts)
- 🤖 Can [be bundled](https://github.com/forensicanalysis/acpack) for automated execution
- 💾 Creates [structured output](https://github.com/forensicanalysis/forensicstore)
- ‍💻 Can run without admin/root rights
- 🕊️ It's open source


### Installation

Download from https://github.com/forensicanalysis/artifactcollector/releases or

```bash
go get -u github.com/forensicanalysis/artifactcollector
```


## Contact

For feedback, questions and discussions you can use the [Open Source DFIR Slack](https://github.com/open-source-dfir/slack).

## Acknowledgment

The development of this software was partially sponsored by Siemens CERT, but
is not an official Siemens product.

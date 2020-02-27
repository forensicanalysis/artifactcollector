// Copyright (c) 2019 Siemens AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Author(s): Jonas Plum

// Package artifactcollector provides a software that collects forensic artifacts
// on systems. These artifacts can be used in forensic investigations to understand
// attacker behavior on compromised computers.
//
// Features
//
// The artifactcollector offers the following features
//    - ️🖥️ Runs on 🖼️ Windows, 🐧 Linux and 🍏 macOS
//    - 🛍️ Can extract files, directories, registry entries, command and WMI output.
//    - ⭐ Uses the configurable and extensible [Forensics Artifacts](https://github.com/forensicanalysis/artifacts)
//    - 💾 Creates [structured output](https://github.com/forensicanalysis/forensicstore)
//    - ‍💻 Can run without admin/root rights
//    - 🕊️ It's open source
package main

import (
	"github.com/forensicanalysis/artifactcollector/assets"
	"github.com/forensicanalysis/artifactcollector/run"
)

//go:generate curl --fail --silent --output fa.zip --location https://github.com/forensicanalysis/artifacts/archive/v0.6.1.zip
//go:generate unzip fa.zip
//go:generate mv artifacts-0.6.1/*.yaml pack/artifacts/
//go:generate rm -rf artifacts-0.6.1 fa.zip
//go:generate go get golang.org/x/tools/cmd/goimports github.com/cugu/go-resources/cmd/resources github.com/akavel/rsrc
//go:generate go run scripts/yaml2go/main.go pack/ac.yaml pack/artifacts/*
//go:generate resources -declare -var=FS -package assets -output assets/assets.go pack/bin/*
//go:generate rsrc -arch amd64 -manifest resources/artifactcollector.exe.manifest -ico resources/artifactcollector.ico -o resources/artifactcollector.syso
//go:generate rsrc -arch 386 -manifest resources/artifactcollector32.exe.manifest -ico resources/artifactcollector.ico -o resources/artifactcollector32.syso
//go:generate rsrc -arch amd64 -manifest resources/artifactcollector.exe.user.manifest -ico resources/artifactcollector.ico -o resources/artifactcollector.user.syso
//go:generate rsrc -arch 386 -manifest resources/artifactcollector32.exe.user.manifest -ico resources/artifactcollector.ico -o resources/artifactcollector32.user.syso

func main() {
	_ = run.Run(assets.Config, assets.Artifacts, assets.FS.Files)
}

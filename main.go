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
// # Features
//
// The artifactcollector offers the following features
//   - ️🖥️ Runs on 🖼️ Windows, 🐧 Linux and 🍏 macOS
//   - 🛍️ Can extract files, directories, registry entries, command and WMI output
//   - ⭐ Uses the configurable and extensible [Forensics Artifacts](https://github.com/forensicanalysis/artifacts)
//   - 💾 Creates a forensicstore as [structured output](https://github.com/forensicanalysis/forensicstore)
//   - 🕊️ Open source
package main

import (
	"os"

	"github.com/forensicanalysis/artifactcollector/assets"
	"github.com/forensicanalysis/artifactcollector/collect"
)

func main() {
	if _, err := collect.Collect(assets.Config, assets.Artifacts, assets.FS); err != nil {
		os.Exit(1)
	}
}

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

package collection

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"

	"github.com/forensicanalysis/forensicstore"
)

func (c *LiveCollector) createProcess(definitionName, cmd string, args []string) *forensicstore.Process {
	process := forensicstore.NewProcess()
	process.Artifact = definitionName
	process.CommandLine = cmd
	process.Name = cmd

	for _, arg := range args {
		process.CommandLine += " " + arg
	}

	stdoutpath, stdoutfile, err := c.Store.StoreFile(path.Join(definitionName, "stdout"))
	if err != nil {
		return process.AddError(err.Error())
	}
	defer stdoutfile.Close()
	process.StdoutPath = filepath.ToSlash(stdoutpath)
	stderrpath, stderrfile, err := c.Store.StoreFile(path.Join(definitionName, "stderr"))
	if err != nil {
		return process.AddError(err.Error())
	}
	defer stderrfile.Close()
	process.StderrPath = filepath.ToSlash(stderrpath)

	// run command
	execution := exec.Command(filepath.Join(c.TempDir, "pack", "bin", cmd), args...) // #nosec
	if _, err := os.Stat(filepath.Join(c.TempDir, "pack", "bin", cmd)); os.IsNotExist(err) {
		process.AddError(fmt.Sprintf("%s is not bundled into artifactcollector, try execution from path", cmd))
		execution = exec.Command(cmd, args...) // #nosec
	}
	execution.Stdout = stdoutfile
	execution.Stderr = stderrfile
	process.CreatedTime = time.Now().UTC().Format(time.RFC3339Nano)
	if err = execution.Run(); err != nil {
		return process.AddError(err.Error())
	}
	return process
}

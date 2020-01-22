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
	"strings"
	"time"

	"github.com/forensicanalysis/forensicstore/goforensicstore"
)

func (c *LiveCollector) createProcess(definitionName, cmd string, args []string) *goforensicstore.Process {
	process := &goforensicstore.Process{}
	process.Artifact = definitionName
	process.Type = "process"
	process.CommandLine = cmd + " " + strings.Join(args, " ")
	process.Name = cmd

	process.Arguments = []interface{}{}
	for _, arg := range args {
		process.Arguments = append(process.Arguments, arg)
	}

	stdoutpath, stdoutfile, err := c.Store.StoreFile(path.Join(definitionName, "stdout"))
	if err != nil {
		return process.AddError(err.Error())
	}
	process.StdoutPath = filepath.ToSlash(stdoutpath)
	stderrpath, stderrfile, err := c.Store.StoreFile(path.Join(definitionName, "stderr"))
	if err != nil {
		return process.AddError(err.Error())
	}
	process.StderrPath = filepath.ToSlash(stderrpath)

	// run command
	execution := exec.Command(filepath.Join(c.TempDir, "pack", "bin", cmd), args...) // #nosec
	if _, err := os.Stat(filepath.Join(c.TempDir, "pack", "bin", cmd)); os.IsNotExist(err) {
		process.AddError(fmt.Sprintf("%s is not bundled into artifactcollector, try execution from path", cmd))
		execution = exec.Command(cmd, args...) // #nosec
	}
	execution.Stdout = stdoutfile
	execution.Stderr = stderrfile
	process.Created = time.Now().Format("2006-01-02T15:04:05.000Z")
	if err = execution.Run(); err != nil {
		return process.AddError(err.Error())
	}
	return process
}

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
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"
)

func (c *LiveCollector) createProcess(definitionName, cmd string, args []string) *Process {
	process := NewProcess()
	process.Artifact = definitionName
	process.CommandLine = cmd
	process.Name = cmd

	for _, arg := range args {
		process.CommandLine += " " + arg
	}

	// setup output destinations
	stdoutPath, stdoutFile, err := c.Store.StoreFile(path.Join(definitionName, "stdout"))
	if err != nil {
		return process.AddError(err.Error())
	}

	process.StdoutPath = filepath.ToSlash(stdoutPath)
	stderrBuf := &bytes.Buffer{}

	// run command
	execution := exec.Command(filepath.Join(c.TempDir, "pack", "bin", cmd), args...) // #nosec

	if _, err := os.Stat(filepath.Join(c.TempDir, "pack", "bin", cmd)); os.IsNotExist(err) {
		process.AddError(fmt.Sprintf("%s is not bundled into artifactcollector, try execution from path", cmd))
		execution = exec.Command(cmd, args...) // #nosec
	}

	execution.Stdout = stdoutFile
	execution.Stderr = stderrBuf
	process.CreatedTime = time.Now().UTC().Format(time.RFC3339Nano)

	if err = execution.Run(); err != nil {
		process.AddError(err.Error())
	}

	// write to stderr
	stderrPath, stderrFile, err := c.Store.StoreFile(path.Join(definitionName, "stderr"))
	if err != nil {
		return process.AddError(err.Error())
	}

	if _, err := io.Copy(stderrFile, stderrBuf); err != nil {
		process.AddError(err.Error())
	}

	process.StderrPath = filepath.ToSlash(stderrPath)

	return process
}

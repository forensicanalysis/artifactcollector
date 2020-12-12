// +build go1.7

// Copyright (c) 2020 Siemens AG
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
	"reflect"
	"runtime"
	"testing"

	"github.com/forensicanalysis/forensicstore"
)

func TestLiveCollector_createProcess(t *testing.T) {
	store, teardown, err := forensicstore.New("file::memory:?mode=memory")
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	type args struct {
		definitionName string
		cmd            string
		args           []string
	}
	tests := []struct {
		name string
		args args
		want *forensicstore.Process
	}{
		{
			"hostname",
			args{"test", "hostname", nil},
			&forensicstore.Process{
				Name:        "hostname",
				Artifact:    "test",
				Type:        "process",
				StdoutPath:  "test/stdout",
				StderrPath:  "test/stderr",
				CommandLine: "hostname",
				ReturnCode:  0,
				Errors:      []interface{}{"hostname is not bundled into artifactcollector, try execution from path"},
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS != "windows" {
				t.Skip()
			}

			c := &LiveCollector{Store: store}
			got := c.createProcess(tt.args.definitionName, tt.args.cmd, tt.args.args)
			got.ID = ""          // unset ID
			got.CreatedTime = "" // unset created
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createProcess() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

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

package collector

import (
	"os"
	"reflect"
	"testing"

	"github.com/forensicanalysis/artifactcollector/store"
)

func TestLiveCollector_createProcess(t *testing.T) {
	f, err := os.CreateTemp("", "test.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	store := store.NewSimpleStore(f)

	type args struct {
		definitionName string
		cmd            string
		args           []string
	}

	tests := []struct {
		name string
		args args
		want *Process
	}{
		{
			"hostname",
			args{"test", "hostname", nil},
			&Process{
				Name:        "hostname",
				Artifact:    "test",
				Type:        "process",
				StdoutPath:  "process/test/stdout",
				StderrPath:  "process/test/stderr",
				CommandLine: "hostname",
				ReturnCode:  0,
				Errors:      []interface{}{"hostname is not bundled into artifactcollector, try execution from path"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Collector{Store: store}
			got := c.createProcess(tt.args.definitionName, tt.args.cmd, tt.args.args)
			got.ID = ""          // unset ID
			got.CreatedTime = "" // unset created

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createProcess() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

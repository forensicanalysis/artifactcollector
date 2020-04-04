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
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/forensicanalysis/artifactlib/goartifacts"
	"github.com/forensicanalysis/forensicstore/goforensicstore"
)

func Test_collectorResolver_Resolve(t *testing.T) {
	windowsEnvironmentVariableSystemRoot := goartifacts.ArtifactDefinition{
		Name: "WindowsEnvironmentVariableSystemRoot",
		Doc:  `The system root directory path, defined by %SystemRoot%, typically "C:\Windows".`,
		Sources: []goartifacts.Source{{
			Type: "PATH",
			Attributes: goartifacts.Attributes{
				Paths:     []string{`\Windows`, `\WinNT`, `\WINNT35`, `\WTSRV`},
				Separator: `\`,
			},
			Provides: []goartifacts.Provide{
				{Key: "environ_systemroot"},
				{Key: "environ_windir"},
				{Key: "environ_systemdrive", Regex: `^(..)`},
			},
		}, {
			Type: "REGISTRY_VALUE",
			Attributes: goartifacts.Attributes{
				KeyValuePairs: []goartifacts.KeyValuePair{{
					Key:   `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion`,
					Value: `SystemRoot`,
				}},
			},
			Provides: []goartifacts.Provide{
				{Key: "environ_systemroot"},
				{Key: "environ_windir"},
				{Key: "environ_systemdrive", Regex: `^(..)`},
			},
		}},
		SupportedOs: []string{"Windows"},
		Urls:        []string{"http://environmentvariables.org/SystemRoot"},
	}

	windowsSystemEventLogEvtx := goartifacts.ArtifactDefinition{
		Name: "WindowsSystemEventLogEvtxFile",
		Doc:  "Windows System Event log for Vista or later systems.",
		Sources: []goartifacts.Source{{
			Type: "FILE",
			Attributes: goartifacts.Attributes{
				Paths:     []string{`%%environ_systemroot%%\System32\winevt\Logs\System.evtx`},
				Separator: `\`,
			},
		}},
		Conditions:  []string{"os_major_version >= 6"},
		Labels:      []string{"Logs"},
		SupportedOs: []string{"Windows"},
		Urls:        []string{"http://www.forensicswiki.org/wiki/Windows_XML_Event_Log_(EVTX)"},
	}

	type args struct {
		parameter string
	}
	tests := []struct {
		name         string
		args         args
		wantResolves []string
		wantErr      bool
		os           string
	}{
		{"Resolve test", args{"environ_systemroot"}, []string{`/C/Windows`}, false, "windows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.os == runtime.GOOS {
				testDir := setup(t)
				defer teardown(t)

				store, err := goforensicstore.NewJSONLite(filepath.Join(testDir, "extract", "ac.forensicstore"))
				if err != nil {
					t.Errorf("Collect() error = %v", err)
					return
				}

				collector, err := NewCollector(store, "", []goartifacts.ArtifactDefinition{windowsSystemEventLogEvtx, windowsEnvironmentVariableSystemRoot})
				if err != nil {
					t.Errorf("NewCollector() error = %v", err)
					return
				}

				gotResolves, err := collector.Resolve(tt.args.parameter)
				if (err != nil) != tt.wantErr {
					t.Errorf("Resolve() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(gotResolves, tt.wantResolves) {
					t.Errorf("Resolve() gotResolves = %v, want %v", gotResolves, tt.wantResolves)
				}
			}
		})
	}
}

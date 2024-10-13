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
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/forensicanalysis/artifactcollector/artifacts"
	"github.com/forensicanalysis/artifactcollector/store"
)

func Test_collectorResolver_Resolve(t *testing.T) {
	windowsEnvironmentVariableSystemRoot := artifacts.ArtifactDefinition{
		Name: "WindowsEnvironmentVariableSystemRoot",
		Doc:  `The system root directory path, defined by %SystemRoot%, typically "C:\Windows".`,
		Sources: []artifacts.Source{{
			Type: "PATH",
			Attributes: artifacts.Attributes{
				Paths:     []string{`\Windows`, `\WinNT`, `\WINNT35`, `\WTSRV`},
				Separator: `\`,
			},
			Provides: []artifacts.Provide{
				{Key: "environ_systemroot"},
				{Key: "environ_windir"},
				{Key: "environ_systemdrive", Regex: `^(..)`},
			},
		}, {
			Type: "REGISTRY_VALUE",
			Attributes: artifacts.Attributes{
				KeyValuePairs: []artifacts.KeyValuePair{{
					Key:   `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion`,
					Value: `SystemRoot`,
				}},
			},
			Provides: []artifacts.Provide{
				{Key: "environ_systemroot"},
				{Key: "environ_windir"},
				{Key: "environ_systemdrive", Regex: `^(..)`},
			},
		}},
		SupportedOs: []string{"Windows"},
		Urls:        []string{"http://environmentvariables.org/SystemRoot"},
	}

	windowsSystemEventLogEvtx := artifacts.ArtifactDefinition{
		Name: "WindowsSystemEventLogEvtxFile",
		Doc:  "Windows System Event log for Vista or later systems.",
		Sources: []artifacts.Source{{
			Type: "FILE",
			Attributes: artifacts.Attributes{
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
		{"Resolve test", args{"environ_systemroot"}, []string{`C/Windows`, `C:\windows`}, false, "windows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.os == runtime.GOOS {
				testDir := setup(t)
				defer teardown(t)

				err := os.MkdirAll(filepath.Join(testDir, "extract"), 0755)
				if err != nil {
					t.Errorf("Could not make dir %s", err)
					return
				}

				f, err := os.CreateTemp("", "test.zip")
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(f.Name())

				store := store.NewSimpleStore(f)

				collector, err := NewCollector(store, "", []artifacts.ArtifactDefinition{windowsSystemEventLogEvtx, windowsEnvironmentVariableSystemRoot})
				if err != nil {
					t.Errorf("NewCollector() error = %v", err)
					return
				}

				gotResolves, err := collector.Resolve(tt.args.parameter)
				if (err != nil) != tt.wantErr {
					t.Errorf("Resolve() error = %v, wantErr %v", err, tt.wantErr)
					return
				}

				sort.Strings(gotResolves)
				sort.Strings(tt.wantResolves)

				if len(gotResolves) != len(tt.wantResolves) {
					t.Errorf("Resolve() gotResolves = %v, want %v", gotResolves, tt.wantResolves)
				}

				for i := range gotResolves {
					if !strings.EqualFold(gotResolves[i], tt.wantResolves[i]) {
						t.Errorf("Resolve() gotResolves = %v, want %v", gotResolves, tt.wantResolves)
					}
				}
			}
		})
	}
}

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
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/forensicanalysis/artifactlib/goartifacts"
	"github.com/forensicanalysis/forensicstore/goforensicstore"
	"github.com/forensicanalysis/fslib"
	"github.com/forensicanalysis/fslib/filesystem/testfs"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

var exampleStore = "example1.forensicstore"

type TestCollector struct {
	fs        fslib.FS
	Collected map[string][]goartifacts.Source
}

func (r *TestCollector) Collect(name string, source goartifacts.Source) {
	source = goartifacts.ExpandSource(source, r)

	if r.Collected == nil {
		r.Collected = map[string][]goartifacts.Source{}
	}
	r.Collected[name] = append(r.Collected[name], source)
}

func (r *TestCollector) FS() fslib.FS {
	return r.fs
}

func (r *TestCollector) Registry() fslib.FS {
	return r.fs
}

func (r *TestCollector) AddPartitions() bool {
	return false
}

func (r *TestCollector) Resolve(s string) ([]string, error) {
	switch s {
	case "foo":
		return []string{"xxx", "yyy"}, nil
	case "faz":
		return []string{"%foo%"}, nil
	}
	return nil, errors.New("could not resolve")
}

func setup(t *testing.T) string {
	dir, err := ioutil.TempDir("", strings.Replace(t.Name(), "/", "_", -1))
	if err != nil {
		log.Fatal("setup tempdir failed ", err)
	}
	input, err := ioutil.ReadFile(filepath.FromSlash("../test/forensicstore/example1.forensicstore/item.db"))
	if err != nil {
		log.Fatal(err)
	}
	err = os.MkdirAll(filepath.Join(dir, exampleStore), 0755)
	if err != nil {
		t.Fatal("setup MkdirAll failed ", err)
	}
	if err := ioutil.WriteFile(filepath.Join(dir, exampleStore, "item.db"), input, 0644); err != nil {
		log.Fatal(err)
	}
	return dir
}

func teardown(t *testing.T) {
	files, err := ioutil.ReadDir(os.TempDir())
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if strings.HasPrefix(f.Name(), strings.Replace(t.Name(), "/", "_", -1)) {
			os.Remove(f.Name())
		}
	}
}

func TestCollect(t *testing.T) {
	// prepare in fs
	sourceFS := &testfs.FS{}
	content := []byte("test")
	dirs := []string{"/dir/a/a/", "/dir/a/b/", "/dir/b/a/", "/dir/b/b/"}
	for _, dir := range dirs {
		sourceFS.CreateDir(dir)
	}
	files := []string{"/foo.txt", "/dir/a/a/foo.txt", "/dir/bar", "/dir/baz", "/dir/a/a/foo.txt", "/dir/a/b/foo.txt", "/dir/b/a/foo.txt", "/dir/b/b/foo.txt"}
	for _, file := range files {
		sourceFS.CreateFile(file, content)
	}

	hashmap := map[string]interface{}{"SHA-1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"}

	type args struct {
		infs     fslib.FS
		out      string
		testfile string
	}
	tests := []struct {
		runOnWindows bool
		name         string
		args         args
		want         int
		wantStorage  []map[string]interface{}
	}{
		{
			true, "Collect simple file", args{sourceFS, "extract", "collect_1.yaml"}, 1,
			[]map[string]interface{}{
				{
					"artifact": "Test1", "type": "file", "name": "foo.txt",
					"origin":      map[string]interface{}{"path": "/foo.txt"},
					"export_path": "extract/Test1/foo.txt", "hashes": hashmap, "size": float64(4),
				},
			},
		},
		{
			false, "Collect registry dummy", args{sourceFS, "extract", "collect_2.yaml"}, 1, nil},
		{
			true, "Collect command dummy", args{sourceFS, "extract", "collect_3.yaml"}, 1,
			[]map[string]interface{}{
				{
					"artifact": "Test3", "type": "process",
					"name": "go", "command_line": "go version", "arguments": []interface{}{"version"},
					"stdout_path": "extract/Test3/stdout",
				},
			},
		},
		{
			true, "Collect directory dummy", args{sourceFS, "extract", "collect_4.yaml"}, 1,
			[]map[string]interface{}{{"artifact": "Test4", "name": "dir", "type": "file", "origin": map[string]interface{}{"path": "/dir"}, "export_path": "extract/Test4/dir"}}},
		{
			false, "Collect registry value dummy", args{sourceFS, "extract", "collect_5.yaml"}, 1, nil},
		{
			true, "Collect with stars", args{sourceFS, "extract", "collect_6.yaml"}, 1,
			[]map[string]interface{}{
				{"artifact": "Test6", "type": "file", "name": "foo.txt", "origin": map[string]interface{}{"path": "/dir/a/a/foo.txt"}, "export_path": "extract/Test6/foo.txt", "size": 4, "hashes": hashmap},
				{"artifact": "Test6", "type": "file", "name": "foo.txt", "origin": map[string]interface{}{"path": "/dir/a/b/foo.txt"}, "export_path": "extract/Test6/foo.txt", "size": 4, "hashes": hashmap},
				{"artifact": "Test6", "type": "file", "name": "foo.txt", "origin": map[string]interface{}{"path": "/dir/b/a/foo.txt"}, "export_path": "extract/Test6/foo.txt", "size": 4, "hashes": hashmap},
				{"artifact": "Test6", "type": "file", "name": "foo.txt", "origin": map[string]interface{}{"path": "/dir/b/b/foo.txt"}, "export_path": "extract/Test6/foo.txt", "size": 4, "hashes": hashmap},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			testDir := setup(t)
			defer teardown(t)

			if runtime.GOOS == "windows" && !tt.runOnWindows {
				t.Skip("Test disabled on windows")
			}

			store, err := goforensicstore.NewJSONLite(filepath.Join(testDir, tt.args.out, "ac.forensicstore"))
			if err != nil {
				t.Errorf("Collect() error = %v", err)
				return
			}

			testFiles := []string{filepath.Join("..", "test", "artifacts", tt.args.testfile)}
			artifactDefinitions, err := goartifacts.DecodeFiles(testFiles)
			if err != nil {
				t.Errorf("Collect() error = %v", err)
				return
			}

			collector := &TestCollector{fs: tt.args.infs}

			for _, artifactDefinition := range artifactDefinitions {
				for _, source := range artifactDefinition.Sources {
					collector.Collect(artifactDefinition.Name, source)
				}
			}

			if len(collector.Collected) != tt.want {
				t.Errorf("Collect() = %v (%v), want %v", len(collector.Collected), collector.Collected, tt.want)
			}

			err = store.Close()
			if err != nil {
				t.Errorf("Collect() error = %v", err)
				return
			}

			// TODO: test extracted file
			/*
				f, err := tt.args.outfs.Open("extract/Test/foo")
				if err != nil {
					t.Errorf("Could not open foo %s", err)
					return
				}
				buf := make([]byte, 4)
				if _, err := f.Read(buf); err != nil {
					t.Errorf("Could not read test file  %s", err)
					return
				}
				if string(content) != string(buf) {
					t.Errorf("Did not collect test file")
				}
			*/

			// test log file
			osfs := afero.NewOsFs()
			_, err = osfs.Open(filepath.Join(testDir, tt.args.out, "ac.forensicstore", "item.db"))
			if !assert.NoErrorf(t, err, "Could not open forensicstore %s", err) {
				return
			}

			/*
				dec := json.NewDecoder(f)
				i := &[]map[string]interface{}{}
				if err := dec.Decode(i); err != nil {
					t.Errorf("Could not decode forensicstore %s", err)
					return
				}

				// do not compare fluctiative timestamps
				for _, r := range *i {
					delete(r, "created")
					delete(r, "modified")
					delete(r, "accessed")
				}
				// TODO: check existence and format of timestamps

				assert.EqualValuesf(t, tt.wantStorage, *i, "Wrong forensicstore")
			*/

		})
	}
}

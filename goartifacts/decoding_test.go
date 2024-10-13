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

package goartifacts

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"reflect"
	"testing"

	"github.com/forensicanalysis/fslib/osfs"
	"gopkg.in/yaml.v2"
)

func TestNewDecoder(t *testing.T) {
	buf := &bytes.Buffer{}

	type args struct {
		r io.Reader
	}

	tests := []struct {
		name string
		args args
		want *Decoder
	}{
		{"New Decoder", args{buf}, &Decoder{nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewDecoder(tt.args.r)
			got.yamldecoder = nil

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDecoder() = %v, want %v", got, tt.want)
			}
		})
	}
}

type failingReadSeeker struct{}

func (r *failingReadSeeker) Read(p []byte) (n int, err error) {
	return 0, errors.New("always fails")
}

func (r *failingReadSeeker) Seek(offset int64, whence int) (int64, error) {
	return 0, errors.New("always fails")
}

func TestDecoder_Decode(t *testing.T) {
	customYaml, _ := os.Open("../test/artifacts/invalid/custom.yaml")

	custom := ArtifactDefinition{
		Name:        "CustomArtifact",
		SupportedOs: []string{"Unknown"},
	}

	validYaml, _ := os.Open("../test/artifacts/valid/valid.yaml")

	goVersionCommand := ArtifactDefinition{
		Name: "GoVersionCommand",
		Doc:  "Minimal dummy artifact definition for tests",
		Sources: []Source{{
			Type: "COMMAND",
			Attributes: Attributes{
				Cmd:  "docker",
				Args: []string{"version"},
			},
		}},
	}

	goInfoCommand := ArtifactDefinition{
		Name: "GoInfoCommand",
		Doc:  "Full Dummy artifact definition for tests",
		Sources: []Source{{
			Type: "COMMAND",
			Attributes: Attributes{
				Cmd:  "docker",
				Args: []string{"info"},
			},
			Conditions:  []string{"time_zone != Pacific/Galapagos"},
			SupportedOs: []string{"Windows", "Linux", "Darwin"},
		}},
		// Provides:    []string{"current_control_set"},
		// Conditions:  []string{"time_zone != Pacific/Galapagos"},
		SupportedOs: []string{"Windows", "Linux", "Darwin"},
		Urls:        []string{"https://docs.docker.com/engine/reference/commandline/info/"},
		Labels:      []string{"Docker"},
	}

	mysteriousCommand := ArtifactDefinition{
		Name: "MysteriousCommand",
		Doc:  "Mysterious command",
		Sources: []Source{{
			Type: "COMMAND",
			Attributes: Attributes{
				Cmd:  "env",
				Args: []string{},
			},
		}},
	}

	type fields struct {
		reader io.ReadSeeker
	}

	tests := []struct {
		name    string
		fields  fields
		want    []ArtifactDefinition
		wantErr bool
	}{
		{"Multi Parse", fields{validYaml}, []ArtifactDefinition{goVersionCommand, goInfoCommand, mysteriousCommand}, false},
		{"Failing Reader", fields{&failingReadSeeker{}}, []ArtifactDefinition{}, true},
		{"Non Strict Parse Custom Fields", fields{customYaml}, []ArtifactDefinition{custom}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &Decoder{
				yamldecoder: yaml.NewDecoder(tt.fields.reader),
			}

			got, err := dec.Decode()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decoder.Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decoder.Decode() = %v, want %v", got, tt.want)
			}

			tt.fields.reader.Seek(0, io.SeekStart) // nolint
		})
	}
}

func TestDecodeFile(t *testing.T) {
	type args struct {
		filename string
	}

	tests := []struct {
		name    string
		args    args
		want    []ArtifactDefinition
		want1   []string
		wantErr bool
	}{
		{"Valid Artifact Definitions", args{"../test/artifacts/valid/mac_os_double_path_3.yaml"}, []ArtifactDefinition{{Name: "Test1Directory", Doc: "Minimal dummy artifact definition for tests", Sources: []Source{{Type: "DIRECTORY", Attributes: Attributes{Paths: []string{"/etc", "/private/etc"}}, SupportedOs: []string{"Darwin"}}}}}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := DecodeFile(tt.args.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodeFile() got = %#v, want %#v", got, tt.want)
			}

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("DecodeFile() got1 = %#v, want %#v", got1, tt.want1)
			}
		})
	}
}

func TestDecodeFiles(t *testing.T) {
	result := []ArtifactDefinition{
		{
			Name: "Test3Directory",
			Doc:  "Minimal dummy artifact definition for tests",
			Sources: []Source{{
				Type: "DIRECTORY", Attributes: Attributes{Paths: []string{"/dev"}}, SupportedOs: []string{"Darwin", "Linux"},
			}},
		},
	}

	type args struct {
		infs      fs.FS
		filenames []string
	}

	tests := []struct {
		name    string
		args    args
		want    []ArtifactDefinition
		wantErr bool
	}{
		{"Valid Artifact Definitions", args{osfs.New(), []string{"../test/artifacts/valid/processing.yaml"}}, result, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ads, err := DecodeFiles(tt.args.filenames)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessFiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(ads, tt.want) {
				t.Errorf("ProcessFiles() got = \n%#v\n, want \n%#v", ads, tt.want)
			}
		})
	}
}

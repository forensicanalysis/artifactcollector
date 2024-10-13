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

package artifacts

import (
	"reflect"
	"runtime"
	"testing"
)

func Test_filterOS(t *testing.T) {
	type args struct {
		artifactDefinitions []ArtifactDefinition
	}

	tests := []struct {
		name string
		args args
		want []ArtifactDefinition
	}{
		{"FilterOS true", args{[]ArtifactDefinition{{Name: "Test", SupportedOs: []string{runtime.GOOS}}}}, []ArtifactDefinition{{Name: "Test", Sources: nil, SupportedOs: []string{runtime.GOOS}}}},
		{"FilterOS sources", args{[]ArtifactDefinition{{Name: "Test", Sources: []Source{{SupportedOs: []string{runtime.GOOS}}, {SupportedOs: []string{"xxx"}}}}}}, []ArtifactDefinition{{Name: "Test", Sources: []Source{{SupportedOs: []string{runtime.GOOS}}}}}},
		{"FilterOS false", args{[]ArtifactDefinition{{Name: "Test", SupportedOs: []string{"xxx"}}}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterOS(tt.args.artifactDefinitions); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterOS() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func Test_isOSArtifactDefinition(t *testing.T) {
	type args struct {
		os          string
		supportedOs []string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{"Test Windows", args{"Windows", []string{"Windows"}}, true},
		{"Test Windows", args{"Windows", []string{"Linux", "Darwin"}}, false},
		{"Test Linux", args{"Linux", []string{"Linux"}}, true},
		{"Test Darwin", args{"Darwin", []string{"Darwin"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsOSArtifactDefinition(tt.args.os, tt.args.supportedOs); got != tt.want {
				t.Errorf("isOSArtifactDefinition() = %v, want %v", got, tt.want)
			}
		})
	}
}

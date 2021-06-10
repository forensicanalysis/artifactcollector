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
	"io"
	"reflect"
	"testing"
)

type storeResetter struct{}

func (s *storeResetter) Write(_ []byte) (int, error) {
	return 0, nil
}

func (s *storeResetter) Close() error {
	return nil
}

func (s *storeResetter) Reset() {}

type storeSeeker struct{}

func (s *storeSeeker) Write(_ []byte) (int, error) {
	return 0, nil
}

func (s *storeSeeker) Close() error {
	return nil
}

// Seek(offset int64, whence int) (int64, error)
func (s *storeSeeker) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func Test_getString(t *testing.T) {

	testMap := map[string]interface{}{
		"test": "I'm a string",
	}

	type args struct {
		m   map[string]interface{}
		key string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "key exists, value is a string",
			args: args{
				m:   testMap,
				key: "test",
			},
			want: "I'm a string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getString(tt.args.m, tt.args.key); got != tt.want {
				t.Errorf("getString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_resetFile_seeker(t *testing.T) {
	type args struct {
		storeFile io.WriteCloser
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "io.Seeker",
			args: args{
				storeFile: &storeSeeker{},
			},
			want: false,
		},
		{
			name: "Resetter",
			args: args{
				storeFile: &storeResetter{},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resetFile(tt.args.storeFile); got != tt.want {
				t.Errorf("resetFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hashCopy(t *testing.T) {
	type args struct {
		src io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    int64
		want1   map[string]interface{}
		wantDst string
		wantErr bool
	}{
		{
			name: "empty string",
			args: args{
				src: bytes.NewBuffer([]byte("")),
			},
			want: 0,
			want1: map[string]interface{}{
				"MD5":     "d41d8cd98f00b204e9800998ecf8427e",
				"SHA-1":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
				"SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			wantDst: "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := &bytes.Buffer{}
			got, got1, err := hashCopy(dst, tt.args.src)
			if (err != nil) != tt.wantErr {
				t.Errorf("hashCopy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("hashCopy() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("hashCopy() got1 = %v, want %v", got1, tt.want1)
			}
			if gotDst := dst.String(); gotDst != tt.wantDst {
				t.Errorf("hashCopy() gotDst = %v, want %v", gotDst, tt.wantDst)
			}
		})
	}
}

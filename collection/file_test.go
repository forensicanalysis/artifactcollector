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
	"io"
	"testing"
)

type storeWriterCloser struct{}

func (s *storeWriterCloser) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func (s *storeWriterCloser) Write(_ []byte) (int, error) {
	return 0, nil
}

func (s *storeWriterCloser) Close() error {
	return nil
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

func Test_resetFile(t *testing.T) {
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
				storeFile: &storeWriterCloser{},
			},
			want: false,
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

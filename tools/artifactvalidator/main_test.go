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

package main

import (
	"reflect"
	"testing"
)

func Test_inc(t *testing.T) {
	type args struct {
		m   map[string]int
		key string
	}
	tests := []struct {
		name string
		args args
		want map[string]int
	}{
		{"Simple inc", args{map[string]int{"a": 2}, "a"}, map[string]int{"a": 3}},
		{"Add key", args{map[string]int{}, "b"}, map[string]int{"b": 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inc(tt.args.m, tt.args.key)
			if !reflect.DeepEqual(tt.args.m, tt.want) {
				t.Errorf("inc() got = %v, want %v", tt.args.m, tt.want)
			}
		})
	}
}

func Test_printTable(t *testing.T) {
	type args struct {
		caption string
		m       map[string]int
	}
	tests := []struct {
		name string
		args args
	}{
		{"Print Table", args{"Table1", map[string]int{"b": 1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			printTable(tt.args.caption, tt.args.m)
		})
	}
}

func Test_sortedMap(t *testing.T) {
	type args struct {
		m map[string]int
	}
	tests := []struct {
		name  string
		args  args
		want  []string
		want1 []string
	}{
		{"Sort map", args{map[string]int{"a": 2, "b": 1}}, []string{"a", "b"}, []string{"2", "1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := sortedMap(tt.args.m)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sortedMap() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("sortedMap() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

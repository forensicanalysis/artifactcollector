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
	"runtime"
	"strings"
	"testing"
)

func TestWMIQuery(t *testing.T) {
	type args struct {
		q string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"OS", args{"SELECT * from Win32_OperatingSystem"}, "C:\\WINDOWS", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS != "windows" {
				t.Skip()
			}

			got, err := WMIQuery(tt.args.q)
			if (err != nil) != tt.wantErr {
				t.Errorf("WMIQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !strings.EqualFold(got[0]["WindowsDirectory"].(string), tt.want) {
				t.Errorf("WMIQuery() got = %v, want %v", got[0]["WindowsDirectory"], tt.want)
			}
		})
	}
}

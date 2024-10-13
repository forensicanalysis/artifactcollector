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

package artifacts

import (
	"errors"
	"io/fs"
)

type TestCollector struct {
	fs        fs.FS
	Collected map[string][]Source
}

func (r *TestCollector) Collect(name string, source Source) {
	source = ExpandSource(source, r)

	if r.Collected == nil {
		r.Collected = map[string][]Source{}
	}

	r.Collected[name] = append(r.Collected[name], source)
}

func (r *TestCollector) FS() fs.FS {
	return r.fs
}

func (r *TestCollector) Registry() fs.FS {
	return r.fs
}

func (r *TestCollector) Prefixes() []string {
	return nil
}

func (r *TestCollector) Resolve(s string) ([]string, error) {
	switch s {
	case "foo":
		return []string{"xxx", "yyy"}, nil
	case "faz":
		return []string{"%foo%"}, nil
	case "environ_systemdrive":
		return []string{"C:"}, nil
	}

	return nil, errors.New("could not resolve")
}

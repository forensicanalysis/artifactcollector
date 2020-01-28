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
	"time"

	"github.com/forensicanalysis/forensicstore/goforensicstore"
)

func (c *LiveCollector) createWMI(definitonName, query string) *goforensicstore.Process {
	process := &goforensicstore.Process{}
	process.Artifact = definitonName
	process.Type = "process"
	process.CommandLine = query
	process.Name = "WMI"
	process.Created = time.Now().Format("2006-01-02T15:04:05.000Z")

	results, err := WMIQuery(query)
	if err != nil {
		return process.AddError(err.Error())
	}

	for _, result := range results {
		process.WMI = append(process.WMI, result)
	}

	return process
}

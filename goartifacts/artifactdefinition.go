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

// Package goartifacts provides functions for parsing and validating forensic
// artifact definition files.
package goartifacts

// A KeyValuePair represents Windows Registry key path and value name that can
// potentially be collected.
type KeyValuePair struct {
	Key   string `yaml:"key,omitempty"`
	Value string `yaml:"value,omitempty"`
}

// Attributes are specific to the type of source definition. They contain
// information.
type Attributes struct {
	Names         []string       `yaml:"names,omitempty"`
	Paths         []string       `yaml:"paths,omitempty"`
	Separator     string         `yaml:"separator,omitempty"`
	Cmd           string         `yaml:"cmd,omitempty"`
	Args          []string       `yaml:"args,omitempty"`
	Keys          []string       `yaml:"keys,omitempty"`
	Query         string         `yaml:"query,omitempty"`
	BaseObject    string         `yaml:"base_object,omitempty"`
	KeyValuePairs []KeyValuePair `yaml:"key_value_pairs,omitempty"`
}

// Provide defines a knowledge base entry that can be created using this source.
type Provide struct {
	Key    string `yaml:"key,omitempty"`
	Regex  string `yaml:"regex,omitempty"`
	WMIKey string `yaml:"wmi_key,omitempty"`
}

// The Source type objects define the source of the artifact data. Currently
// the following source types are defined:
//
//   - artifact; the source is one or more artifact definitions;
//   - file; the source is one or more files;
//   - path; the source is one or more paths;
//   - directory; the source is one or more directories;
//   - Windows Registry key; the source is one or more Windows Registry keys;
//   - Windows Registry value; the source is one or more Windows Registry values;
//   - WMI query; the source is a Windows Management Instrumentation query.
//
// The difference between the file and path source types are that file should
// be used to define file entries that contain data and path, file entries that
// define a location. E.g. on Windows %SystemRoot% could be considered a path
// artifact definition, pointing to a location e.g. C:\\Windows. And where
// C:\\Windows\\System32\\winevt\\Logs\\AppEvent.evt a file artifact definition,
// pointing to the Application Event Log file.
type Source struct {
	Type        string     `yaml:"type,omitempty"`
	Attributes  Attributes `yaml:"attributes,omitempty"`
	Conditions  []string   `yaml:"conditions,omitempty"`
	SupportedOs []string   `yaml:"supported_os,omitempty"`
	Provides    []Provide  `yaml:"provides,omitempty"`
}

// The ArtifactDefinition describes an object of digital archaeological interest.
type ArtifactDefinition struct {
	Name        string   `yaml:"name,omitempty"`
	Doc         string   `yaml:"doc,omitempty"`
	Sources     []Source `yaml:"sources,omitempty"`
	Conditions  []string `yaml:"conditions,omitempty"`
	Provides    []string `yaml:"provides,omitempty"`
	Labels      []string `yaml:"labels,omitempty"`
	SupportedOs []string `yaml:"supported_os,omitempty"`
	Urls        []string `yaml:"urls,omitempty"`
}

// SourceType is an enumeration of artifact definition source types.
var SourceType = struct {
	ArtifactGroup string
	Command       string
	Directory     string
	File          string
	Path          string
	RegistryKey   string
	RegistryValue string
	Wmi           string
}{
	ArtifactGroup: "ARTIFACT_GROUP",
	Command:       "COMMAND",
	Directory:     "DIRECTORY",
	File:          "FILE",
	Path:          "PATH",
	RegistryKey:   "REGISTRY_KEY",
	RegistryValue: "REGISTRY_VALUE",
	Wmi:           "WMI",
}

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

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/forensicanalysis/artifactcollector/artifacts"
	"github.com/forensicanalysis/artifactcollector/collector"
)

func artifacts2go(artifactDefinitionFiles []string) ([]artifacts.ArtifactDefinition, error) {
	var artifactDefinitions []artifacts.ArtifactDefinition

	for _, artifactDefinitionFile := range artifactDefinitionFiles {
		// parse artifact definition yaml
		data, err := os.Open(artifactDefinitionFile) // #nosec
		if err != nil {
			return nil, err
		}

		decoder := yaml.NewDecoder(data)

		for {
			artifactDefinition := artifacts.ArtifactDefinition{}

			err := decoder.Decode(&artifactDefinition)
			if err == io.EOF {
				break
			}

			if err != nil {
				return nil, fmt.Errorf("decode of %s failed: %w", artifactDefinitionFile, err)
			}

			for i := range artifactDefinition.Sources {
				artifactDefinition.Sources[i].Parent = artifactDefinition.Name
			}

			artifactDefinitions = append(artifactDefinitions, artifactDefinition)
		}
	}

	return artifactDefinitions, nil
}

func createGoFile(pkg, name string, objects interface{}) error {
	// write go code to assets go
	err := os.MkdirAll(pkg, 0750)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(pkg, name+".generated.go"))
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(f, "package %s \nvar %s = %#v", pkg, strings.Title(name), objects)
	if err != nil {
		return err
	}

	// add imports
	cmd := exec.Command("goimports", "-w", filepath.Join(pkg, name+".generated.go")) // #nosec

	return cmd.Run()
}

func main() {
	configFile := os.Args[1]

	configYaml, err := os.ReadFile(configFile) // #nosec
	if err != nil {
		log.Fatal(err)
	}

	config := &collector.Configuration{}

	err = yaml.Unmarshal(configYaml, config)
	if err != nil {
		log.Fatal(err)
	}

	err = createGoFile("assets", "config", config)
	if err != nil {
		log.Fatal(err)
	}

	var artifactDefinitionFiles []string

	for _, adarg := range os.Args[2:] {
		out, err := filepath.Glob(adarg)
		if err != nil {
			log.Fatal(err)
		}

		artifactDefinitionFiles = append(artifactDefinitionFiles, out...)
	}

	artifactDefinitions, err := artifacts2go(artifactDefinitionFiles)
	if err != nil {
		log.Fatal(err)
	}

	// decode file
	for _, filename := range artifactDefinitionFiles {
		if _, _, err := artifacts.DecodeFile(filename); err != nil {
			log.Fatal(err)
		}
	}

	err = createGoFile("assets", "artifacts", artifactDefinitions)
	if err != nil {
		log.Fatal(err)
	}
}

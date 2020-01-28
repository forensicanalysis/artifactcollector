package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/forensicanalysis/artifactcollector/collection"
	"github.com/forensicanalysis/artifactlib/goartifacts"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

func artifacts2go(artifactDefinitionFiles []string) ([]goartifacts.ArtifactDefinition, error) {
	var artifactDefinitions []goartifacts.ArtifactDefinition
	for _, artifactDefinitionFile := range artifactDefinitionFiles {
		// parse artifact definition yaml
		data, err := os.Open(artifactDefinitionFile)
		if err != nil {
			return nil, err
		}
		decoder := yaml.NewDecoder(data)

		for {
			artifactDefinition := goartifacts.ArtifactDefinition{}
			err := decoder.Decode(&artifactDefinition)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("decode of %s failed", artifactDefinitionFile))
			}

			artifactDefinitions = append(artifactDefinitions, artifactDefinition)
		}
	}
	return artifactDefinitions, nil

}

func createGoFile(pkg, name string, objects interface{}) error {
	// write go code to assets go
	err := os.MkdirAll(pkg, 0777)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(pkg, name+".go"))
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(f, "package %s \nvar %s = %#v", pkg, strings.Title(name), objects)
	if err != nil {
		return err
	}

	// add imports
	cmd := exec.Command("goimports", "-w", filepath.Join(pkg, name+".go"))
	return cmd.Run()
}

func main() {
	configFile := os.Args[1]
	configYaml, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	config := &collection.Configuration{}
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

	flaws, err := goartifacts.ValidateFiles(artifactDefinitionFiles)
	if err != nil {
		log.Fatal(err)
	}
	for _, flaw := range flaws {
		if flaw.Severity != goartifacts.Common {
			log.Println(flaw.File, flaw.ArtifactDefinition, ":", flaw.Message)
		}
	}

	err = createGoFile("assets", "artifacts", artifactDefinitions)
	if err != nil {
		log.Fatal(err)
	}
}

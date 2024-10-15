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
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/looplab/tarjan"

	"github.com/forensicanalysis/artifactcollector/artifacts"
)

// Severity level of a flaw.
type Severity int

// Severity levels of a flaw.
const (
	Common  Severity = iota // Common errors
	Info                    // Style violations, will not create any issues
	Warning                 // Will compile but might create unexpected results
	Error                   // Will likely become an error
)

// Flaw is a single issue found by the validator.
type Flaw struct {
	Severity           Severity
	Message            string
	ArtifactDefinition string
	File               string
}

// The validator performs all validations and stores the found flaws.
type validator struct {
	flaws []Flaw
}

func newValidator() *validator {
	return &validator{[]Flaw{}}
}

func (r *validator) addFlawf(filename, artifactDefiniton string, severity Severity, format string, a ...interface{}) {
	r.flaws = append(
		r.flaws,
		Flaw{Severity: severity, Message: fmt.Sprintf(format, a...), ArtifactDefinition: artifactDefiniton, File: filename},
	)
}

func (r *validator) addCommonf(filename, artifactDefiniton, format string, a ...interface{}) {
	r.addFlawf(filename, artifactDefiniton, Common, format, a...)
}

func (r *validator) addInfof(filename, artifactDefiniton, format string, a ...interface{}) {
	r.addFlawf(filename, artifactDefiniton, Info, format, a...)
}

func (r *validator) addWarningf(filename, artifactDefiniton, format string, a ...interface{}) {
	r.addFlawf(filename, artifactDefiniton, Warning, format, a...)
}

func (r *validator) addErrorf(filename, artifactDefiniton, format string, a ...interface{}) {
	r.addFlawf(filename, artifactDefiniton, Error, format, a...)
}

// ValidateFiles checks a list of files for various flaws.
func ValidateFiles(filenames []string) (flaws []Flaw, err error) {
	artifactDefinitionMap := map[string][]artifacts.ArtifactDefinition{}

	// decode file
	for _, filename := range filenames {
		ads, typeErrors, err := artifacts.DecodeFile(filename)
		if err != nil {
			return flaws, err
		}
		artifactDefinitionMap[filename] = ads
		for _, typeError := range typeErrors {
			flaws = append(flaws, Flaw{Error, typeError, "", filename})
		}
	}

	// validate
	flaws = append(flaws, ValidateArtifactDefinitions(artifactDefinitionMap)...)
	return
}

// ValidateArtifactDefinitions validates a map of artifact definitions and returns any flaws found in those.
func ValidateArtifactDefinitions(artifactDefinitionMap map[string][]artifacts.ArtifactDefinition) []Flaw {
	r := newValidator()
	r.validateArtifactDefinitions(artifactDefinitionMap)
	return r.flaws
}

// validateArtifactDefinitions validates single artifacts.
func (r *validator) validateArtifactDefinitions(artifactDefinitionMap map[string][]artifacts.ArtifactDefinition) {
	var globalArtifactDefinitions []artifacts.ArtifactDefinition

	for filename, artifactDefinitions := range artifactDefinitionMap {
		if filename != "" {
			r.validateSyntax(filename)
		}

		globalArtifactDefinitions = append(globalArtifactDefinitions, artifactDefinitions...)
		for _, artifactDefinition := range artifactDefinitions {
			r.validateArtifactDefinition(filename, artifactDefinition)
		}
	}

	// global validations
	r.validateNameUnique(globalArtifactDefinitions)
	r.validateRegistryKeyUnique(globalArtifactDefinitions)
	r.validateRegistryValueUnique(globalArtifactDefinitions)
	r.validateGroupMemberExist(globalArtifactDefinitions)
	r.validateNoCycles(globalArtifactDefinitions)
	r.validateParametersProvided(globalArtifactDefinitions)

	r.validateArtifactURLs(artifactDefinitionMap)
}

// validateArtifactDefinition validates a single artifact.
func (r *validator) validateArtifactDefinition(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	windowsArtifact := artifacts.IsOSArtifactDefinition(supportedOS.Windows, artifactDefinition.SupportedOs)
	linuxArtifact := artifacts.IsOSArtifactDefinition(supportedOS.Linux, artifactDefinition.SupportedOs)
	macosArtifact := artifacts.IsOSArtifactDefinition(supportedOS.Darwin, artifactDefinition.SupportedOs)

	r.validateNameCase(filename, artifactDefinition)
	r.validateNameTypeSuffix(filename, artifactDefinition)
	r.validateDocLong(filename, artifactDefinition)
	r.validateNamePrefix(filename, artifactDefinition)
	r.validateOSSpecific(filename, artifactDefinition)
	r.validateArtifactOS(filename, artifactDefinition)
	r.validateNoDefinitionConditions(filename, artifactDefinition)
	r.validateNoDefinitionProvides(filename, artifactDefinition)
	if macosArtifact {
		r.validateMacOSDoublePath(filename, artifactDefinition)
	}

	// validate sources
	for _, source := range artifactDefinition.Sources {
		windowsSource := artifacts.IsOSArtifactDefinition(supportedOS.Windows, source.SupportedOs)
		linuxSource := artifacts.IsOSArtifactDefinition(supportedOS.Linux, source.SupportedOs)
		macosSource := artifacts.IsOSArtifactDefinition(supportedOS.Darwin, source.SupportedOs)

		r.validateUnnessesarryAttributes(filename, artifactDefinition.Name, source)
		r.validateRequiredAttributes(filename, artifactDefinition.Name, source)
		r.validateDeprecatedVars(filename, artifactDefinition.Name, source)
		r.validateRegistryCurrentControlSet(filename, artifactDefinition.Name, source)
		r.validateRegistryHKEYCurrentUser(filename, artifactDefinition.Name, source)
		// r.validateDoubleStar(filename, artifactDefinition.Name, source)
		r.validateSourceOS(filename, artifactDefinition.Name, source)
		r.validateSourceType(filename, artifactDefinition.Name, source)
		r.validateParameter(filename, artifactDefinition.Name, source)
		r.validateSourceProvides(filename, artifactDefinition.Name, source)

		if windowsArtifact && windowsSource {
			r.validateNoWindowsHomedir(filename, artifactDefinition.Name, source)
			r.validateRequiredWindowsAttributes(filename, artifactDefinition.Name, source)
		}
		if (linuxArtifact || macosArtifact) && (linuxSource || macosSource) {
			r.validateRequiredNonWindowsAttributes(filename, artifactDefinition.Name, source)
		}
	}
}

func (r *validator) validateSyntax(filename string) {
	if !strings.HasSuffix(filename, ".yaml") {
		r.addInfof(filename, "", "File should have .yaml ending")
	}

	// open file
	f, err := os.Open(filename) // #nosec
	if err != nil {
		r.addErrorf(filename, "", "Error %s", err)
		return
	}
	defer f.Close()
	i := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if i == 0 {
			if len(line) < 3 || !strings.HasPrefix(line, "# ") {
				r.addInfof(filename, "", "The first line should be a comment")
			}
		}

		if line != strings.TrimRight(line, " \t") {
			r.addInfof(filename, "", "Line %d ends with whitespace", i+1)
		}
		i++
	}
}

// global

func (r *validator) validateNameUnique(artifactDefinitions []artifacts.ArtifactDefinition) {
	knownNames := map[string]bool{}
	for _, artifactDefinition := range artifactDefinitions {
		if _, ok := knownNames[artifactDefinition.Name]; ok {
			r.addWarningf("", artifactDefinition.Name, "Duplicate artifact name %s", artifactDefinition.Name)
		} else {
			knownNames[artifactDefinition.Name] = true
		}
	}
}

func (r *validator) validateRegistryKeyUnique(artifactDefinitions []artifacts.ArtifactDefinition) {
	knownKeys := map[string]bool{}
	for _, artifactDefinition := range artifactDefinitions {
		for _, source := range artifactDefinition.Sources {
			for _, key := range source.Attributes.Keys {
				if _, ok := knownKeys[key]; ok {
					r.addWarningf("", artifactDefinition.Name, "Duplicate registry key %s", key)
				} else {
					knownKeys[key] = true
				}
			}
		}
	}
}

func (r *validator) validateRegistryValueUnique(artifactDefinitions []artifacts.ArtifactDefinition) {
	knownKeys := map[string]bool{}
	for _, artifactDefinition := range artifactDefinitions {
		for _, source := range artifactDefinition.Sources {
			for _, keyvalue := range source.Attributes.KeyValuePairs {
				if _, ok := knownKeys[keyvalue.Key+"/"+keyvalue.Value]; ok {
					r.addWarningf(
						"", artifactDefinition.Name, "Duplicate registry value %s %s",
						keyvalue.Key, keyvalue.Value,
					)
				} else {
					knownKeys[keyvalue.Key+"/"+keyvalue.Value] = true
				}
			}
		}
	}
}

func (r *validator) validateNoCycles(artifactDefinitions []artifacts.ArtifactDefinition) {
	graph := make(map[interface{}][]interface{})
	for _, artifactDefinition := range artifactDefinitions {
		for _, source := range artifactDefinition.Sources {
			if source.Type == artifacts.SourceType.ArtifactGroup {
				graph[artifactDefinition.Name] = []interface{}{}
				for _, name := range source.Attributes.Names {
					if name == artifactDefinition.Name {
						r.addErrorf("", artifactDefinition.Name, "Artifact group references itself")
					}
					graph[artifactDefinition.Name] = append(graph[artifactDefinition.Name], name)
				}
			}
		}
	}

	output := tarjan.Connections(graph)
	for _, subgraph := range output {
		if len(subgraph) > 1 {
			var sortedSubgraph []string
			for _, subgraphitem := range subgraph {
				sortedSubgraph = append(sortedSubgraph, subgraphitem.(string))
			}
			sort.Strings(sortedSubgraph)
			r.addErrorf("", "", "Cyclic artifact group: %s", sortedSubgraph)
		}
	}
}

func (r *validator) validateGroupMemberExist(artifactDefinitions []artifacts.ArtifactDefinition) {
	knownNames := map[string]bool{}
	for _, artifactDefinition := range artifactDefinitions {
		knownNames[artifactDefinition.Name] = true
	}

	for _, artifactDefinition := range artifactDefinitions {
		for _, source := range artifactDefinition.Sources {
			for _, member := range source.Attributes.Names {
				if _, ok := knownNames[member]; !ok {
					r.addErrorf(
						"", artifactDefinition.Name,
						"Unknown name %s in %s", member, artifactDefinition.Name,
					)
				}
			}
		}
	}
}

func (r *validator) validateParametersProvided(artifactDefinitions []artifacts.ArtifactDefinition) { // nolint:gocyclo,gocognit
	parametersRequired := map[string]map[string]string{
		"Windows": {},
		"Darwin":  {},
		"Linux":   {},
		"ESXi":    {},
	}
	regex := regexp.MustCompile(`%?%(.*?)%?%`)

	for _, artifactDefinition := range artifactDefinitions {
		for _, source := range artifactDefinition.Sources {
			for _, path := range source.Attributes.Paths {
				for _, match := range regex.FindAllStringSubmatch(path, -1) {
					for _, operatingSystem := range getSupportedOS(artifactDefinition, source) {
						parametersRequired[operatingSystem][match[1]] = artifactDefinition.Name
					}
				}
			}

			for _, key := range source.Attributes.Keys {
				for _, match := range regex.FindAllStringSubmatch(key, -1) {
					for _, operatingSystem := range getSupportedOS(artifactDefinition, source) {
						parametersRequired[operatingSystem][match[1]] = artifactDefinition.Name
					}
				}
			}
		}
	}

	knownProvides := map[string]map[string]string{
		"Windows": {},
		"Darwin":  {},
		"Linux":   {},
		"ESXi":    {},
	}

	for _, artifactDefinition := range artifactDefinitions {
		for _, source := range artifactDefinition.Sources {
			for _, provide := range source.Provides {
				for _, operatingSystem := range getSupportedOS(artifactDefinition, source) {
					knownProvides[operatingSystem][provide.Key] = artifactDefinition.Name
				}
			}
		}
	}

	for operatingSystem := range parametersRequired {
		for parameter := range parametersRequired[operatingSystem] {
			if _, ok := knownProvides[operatingSystem][parameter]; !ok {
				r.addWarningf(
					"", parametersRequired[operatingSystem][parameter],
					"Parameter %s is not provided for %s", parameter, operatingSystem,
				)
			}
		}
	}
}

func (r *validator) validateArtifactURLs(artifactDefinitionMap map[string][]artifacts.ArtifactDefinition) {
	var jobWaitGroup sync.WaitGroup

	type urlJob struct {
		filename string
		artifact string
		url      string
	}

	type urlResult struct {
		filename string
		artifact string
		err      string
	}

	const numJobs = 1000
	jobs := make(chan urlJob, numJobs)
	results := make(chan urlResult, numJobs)

	// process urls
	go func() {
		for w := 1; w <= 40; w++ {
			jobWaitGroup.Add(1)
			go func() {
				defer jobWaitGroup.Done()
				for j := range jobs {
					req, err := http.NewRequest(http.MethodGet, j.url, nil)
					if err != nil {
						results <- urlResult{filename: j.filename, artifact: j.artifact, err: fmt.Sprintf("Error creating request for %s: %s", j.url, err)}
						continue
					}

					client := &http.Client{Timeout: time.Second * 10}

					resp, err := client.Do(req)
					if err != nil {
						results <- urlResult{filename: j.filename, artifact: j.artifact, err: fmt.Sprintf("Error retrieving url %s: %s", j.url, err)}
						continue
					}

					if resp.StatusCode != http.StatusOK {
						results <- urlResult{filename: j.filename, artifact: j.artifact, err: fmt.Sprintf("Status code retrieving url %s was %d", j.url, resp.StatusCode)}
					}

					if err := resp.Body.Close(); err != nil {
						results <- urlResult{filename: j.filename, artifact: j.artifact, err: fmt.Sprintf("Error closing body for %s: %s", j.url, err)}
					}
				}
			}()
		}
		jobWaitGroup.Wait()
		close(results)
	}()

	for filename, artifactDefinitions := range artifactDefinitionMap {
		for _, artifactDefinition := range artifactDefinitions {
			for _, u := range artifactDefinition.Urls {
				jobs <- urlJob{
					filename: filename,
					artifact: artifactDefinition.Name,
					url:      u,
				}
			}
		}
	}
	close(jobs)

	for res := range results {
		r.addCommonf(res.filename, res.artifact, res.err)
	}
}

// file

func (r *validator) validateNamePrefix(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	prefix := ""
	switch {
	case strings.HasPrefix(filepath.Base(filename), "windows"):
		prefix = "Windows"
	case strings.HasPrefix(filepath.Base(filename), "linux"):
		prefix = "Linux"
	case strings.HasPrefix(filepath.Base(filename), "macos"):
		prefix = "MacOS"
	}
	if !strings.HasPrefix(artifactDefinition.Name, prefix) {
		r.addCommonf(filename, artifactDefinition.Name, "Artifact name should start with %s", prefix)
	}
}

func (r *validator) validateOSSpecific(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	operatingSystem := ""
	switch {
	case strings.HasPrefix(filepath.Base(filename), "windows"):
		operatingSystem = supportedOS.Windows
	case strings.HasPrefix(filepath.Base(filename), "linux"):
		operatingSystem = supportedOS.Linux
	case strings.HasPrefix(filepath.Base(filename), "macos"):
		operatingSystem = supportedOS.Darwin
	}
	if operatingSystem == "" {
		return
	}

	for _, supportedOs := range artifactDefinition.SupportedOs {
		if supportedOs != operatingSystem {
			r.addInfof(
				filename, artifactDefinition.Name,
				"File should only contain %s artifact definitions", operatingSystem,
			)
		}
	}
	for _, source := range artifactDefinition.Sources {
		for _, supportedOs := range source.SupportedOs {
			if supportedOs != operatingSystem {
				r.addInfof(
					filename, artifactDefinition.Name,
					"File should only contain %s artifact definitions", operatingSystem,
				)
			}
		}
	}
}

// artifact

func (r *validator) validateNameCase(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	if len(artifactDefinition.Name) < 2 { //nolint:gomnd
		r.addErrorf(filename, artifactDefinition.Name, "Artifact names need be longer than 2 characters")
		return
	}
	if strings.HasPrefix(artifactDefinition.Name, "vSphere") || strings.HasPrefix(artifactDefinition.Name, "vCenter") {
		return
	}
	if strings.ToUpper(artifactDefinition.Name[:1]) != artifactDefinition.Name[:1] {
		r.addInfof(filename, artifactDefinition.Name, "Artifact names should be CamelCase")
	}
	if strings.ContainsAny(artifactDefinition.Name, " \t") {
		r.addInfof(filename, artifactDefinition.Name, "Artifact names should not contain whitespace")
	}
}

func (r *validator) validateNameTypeSuffix(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	if len(artifactDefinition.Sources) == 0 {
		r.addErrorf(filename, artifactDefinition.Name, "Artifact has no sources")
		return
	}
	currentSourceType := artifactDefinition.Sources[0].Type
	for _, source := range artifactDefinition.Sources {
		if source.Type != currentSourceType {
			return
		}
	}

	endings := map[string][]string{
		artifacts.SourceType.Command:       {"Command", "Commands"},
		artifacts.SourceType.Directory:     {"Directory", "Directories"},
		artifacts.SourceType.File:          {"File", "Files"},
		artifacts.SourceType.Path:          {"Path", "Paths"},
		artifacts.SourceType.RegistryKey:   {"RegistryKey", "RegistryKeys"},
		artifacts.SourceType.RegistryValue: {"RegistryValue", "RegistryValues"},
	}

	if _, ok := endings[currentSourceType]; !ok {
		return
	}

	trimmed := strings.TrimSpace(artifactDefinition.Name)
	ending := endings[currentSourceType]
	if !strings.HasSuffix(trimmed, ending[0]) && !strings.HasSuffix(trimmed, ending[1]) {
		r.addCommonf(
			filename, artifactDefinition.Name,
			"Artifact name should end in %s", strings.Join(ending, " or "),
		)
	}
}

func (r *validator) validateDocLong(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	if strings.Contains(artifactDefinition.Doc, "\n") && !strings.Contains(artifactDefinition.Doc, "\n\n") {
		r.addInfof(filename, artifactDefinition.Name, "Long docs should contain an empty line")
	}
}

func (r *validator) validateArtifactOS(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	for _, supportedos := range artifactDefinition.SupportedOs {
		found := false
		for _, os := range listOSS() {
			if os == supportedos {
				found = true
			}
		}
		if !found {
			r.addWarningf(filename, artifactDefinition.Name, "OS %s is not valid", supportedos)
		}
	}
}

func (r *validator) validateNoDefinitionConditions(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	if len(artifactDefinition.Conditions) > 0 {
		r.addInfof(filename, artifactDefinition.Name, "Definition conditions are deprecated")
	}
}

func (r *validator) validateNoDefinitionProvides(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	if len(artifactDefinition.Provides) > 0 {
		r.addInfof(filename, artifactDefinition.Name, "Definition provides are deprecated")
	}
}

func (r *validator) validateMacOSDoublePath(filename string, artifactDefinition artifacts.ArtifactDefinition) {
	knownPaths := map[string]bool{}
	prefixes := []string{"/var", "/tmp", "/etc"}

	if artifacts.IsOSArtifactDefinition("Darwin", artifactDefinition.SupportedOs) {
		for _, source := range artifactDefinition.Sources {
			if artifacts.IsOSArtifactDefinition("Darwin", source.SupportedOs) {
				for _, path := range source.Attributes.Paths {
					for _, prefix := range prefixes {
						if strings.HasPrefix(path, prefix) || strings.HasPrefix(path, "/private"+prefix) {
							knownPaths[path] = true
						}
					}
				}
			}
		}
	}

	for knownPath := range knownPaths {
		var sibling string
		if strings.HasPrefix(knownPath, "/private") {
			sibling = strings.Replace(knownPath, "/private", "", 1)
		} else {
			sibling = "/private" + knownPath
		}
		if _, ok := knownPaths[sibling]; !ok {
			r.addWarningf(filename, artifactDefinition.Name, "Found %s but not %s", knownPath, sibling)
		}
	}
}

// source

func (r *validator) validateUnnessesarryAttributes(filename, artifactDefinition string, source artifacts.Source) { // nolint:gocyclo,lll
	hasNames := len(source.Attributes.Names) > 0
	hasCommand := source.Attributes.Cmd != "" || len(source.Attributes.Args) > 0
	hasPaths := len(source.Attributes.Paths) > 0 || source.Attributes.Separator != ""
	hasKeys := len(source.Attributes.Keys) > 0
	hasKeyValuePairs := len(source.Attributes.KeyValuePairs) > 0
	hasWMI := source.Attributes.Query != "" || source.Attributes.BaseObject != ""

	switch source.Type {
	case artifacts.SourceType.ArtifactGroup:
		if hasPaths || hasCommand || hasKeys || hasWMI || hasKeyValuePairs {
			r.addWarningf(filename, artifactDefinition, "Unnessesarry attribute set")
		}
	case artifacts.SourceType.Command:
		if hasNames || hasPaths || hasKeys || hasWMI || hasKeyValuePairs {
			r.addWarningf(filename, artifactDefinition, "Unnessesarry attribute set")
		}
	case artifacts.SourceType.Directory:
		fallthrough
	case artifacts.SourceType.File:
		fallthrough
	case artifacts.SourceType.Path:
		if hasNames || hasCommand || hasKeys || hasWMI || hasKeyValuePairs {
			r.addWarningf(filename, artifactDefinition, "Unnessesarry attribute set")
		}
	case artifacts.SourceType.RegistryKey:
		if hasNames || hasPaths || hasCommand || hasWMI || hasKeyValuePairs {
			r.addWarningf(filename, artifactDefinition, "Unnessesarry attribute set")
		}
	case artifacts.SourceType.RegistryValue:
		if hasNames || hasPaths || hasCommand || hasKeys || hasWMI {
			r.addWarningf(filename, artifactDefinition, "Unnessesarry attribute set")
		}
	case artifacts.SourceType.Wmi:
		if hasNames || hasPaths || hasCommand || hasKeys || hasKeyValuePairs {
			r.addWarningf(filename, artifactDefinition, "Unnessesarry attribute set")
		}
	}
}

func (r *validator) validateRequiredAttributes(filename, artifactDefinition string, source artifacts.Source) {
	switch source.Type {
	case artifacts.SourceType.ArtifactGroup:
		if len(source.Attributes.Names) == 0 {
			r.addWarningf(filename, artifactDefinition, "An ARTIFACT_GROUP requires the names attribute")
		}
	case artifacts.SourceType.Command:
		if source.Attributes.Cmd == "" {
			r.addWarningf(filename, artifactDefinition, "A COMMAND requires the cmd attribute")
		}
	}
}

func (r *validator) validateRequiredWindowsAttributes(filename, artifactDefinition string, source artifacts.Source) {
	switch source.Type {
	case artifacts.SourceType.Directory:
		fallthrough
	case artifacts.SourceType.File:
		fallthrough
	case artifacts.SourceType.Path:
		if len(source.Attributes.Paths) == 0 {
			r.addWarningf(filename, artifactDefinition, "A %s requires the paths attribute", source.Type)
		}
		if source.Attributes.Separator != "" && source.Attributes.Separator != "\\" {
			r.addWarningf(
				filename, artifactDefinition,
				"A %s requires a separator value of \"\\\" or \"\"", source.Type,
			)
		}
	case artifacts.SourceType.RegistryKey:
		if len(source.Attributes.Keys) == 0 {
			r.addWarningf(filename, artifactDefinition, "A %s requires the keys attribute", source.Type)
		}
	case artifacts.SourceType.RegistryValue:
		if len(source.Attributes.KeyValuePairs) == 0 {
			r.addWarningf(filename, artifactDefinition, "A %s requires the key_value_pairs attribute", source.Type)
		}
	case artifacts.SourceType.Wmi:
		if len(source.Attributes.Query) == 0 {
			r.addWarningf(filename, artifactDefinition, "A %s requires the query attribute", source.Type)
		}
	}
}

func (r *validator) validateRequiredNonWindowsAttributes(filename, artifactDefinition string, source artifacts.Source) {
	switch source.Type {
	case artifacts.SourceType.Directory:
		fallthrough
	case artifacts.SourceType.File:
		fallthrough
	case artifacts.SourceType.Path:
		if len(source.Attributes.Paths) == 0 {
			r.addWarningf(filename, artifactDefinition, "A %s requires the paths attribute", source.Type)
		}
	case artifacts.SourceType.RegistryKey:
		fallthrough
	case artifacts.SourceType.RegistryValue:
		fallthrough
	case artifacts.SourceType.Wmi:
		r.addErrorf(filename, artifactDefinition, "%s only supported for windows", source.Type)
	}
}

func (r *validator) validateRegistryCurrentControlSet(filename, artifactDefinition string, source artifacts.Source) {
	err := `Registry key should not start with %%CURRENT_CONTROL_SET%%. `
	err += `Replace %%CURRENT_CONTROL_SET%% with HKEY_LOCAL_MACHINE\\System\\CurrentControlSet`

	for _, key := range source.Attributes.Keys {
		if strings.Contains(key, `%%CURRENT_CONTROL_SET%%`) {
			r.addInfof(filename, artifactDefinition, err)
		}
	}
	for _, keyvalue := range source.Attributes.KeyValuePairs {
		if strings.Contains(keyvalue.Key, `%%CURRENT_CONTROL_SET%%`) {
			r.addInfof(filename, artifactDefinition, err)
		}
	}
}

func (r *validator) validateRegistryHKEYCurrentUser(filename, artifactDefinition string, source artifacts.Source) {
	err := `HKEY_CURRENT_USER\\ is not supported instead use: HKEY_USERS\\%%users.sid%%\\`
	for _, key := range source.Attributes.Keys {
		if strings.HasPrefix(key, `HKEY_CURRENT_USER\\`) {
			r.addErrorf(filename, artifactDefinition, err)
		}
	}
	for _, keyvalue := range source.Attributes.KeyValuePairs {
		if strings.HasPrefix(keyvalue.Key, `HKEY_CURRENT_USER\\`) {
			r.addErrorf(filename, artifactDefinition, err)
		}
	}
}

func (r *validator) validateDeprecatedVars(filename, artifactDefinition string, source artifacts.Source) {
	deprecations := []struct {
		old, new string
	}{
		{old: "%%users.userprofile%%\\AppData\\Local", new: "%%users.localappdata%%"},
		{old: "%%users.userprofile%%\\AppData\\Roaming", new: "%%users.appdata%%"},
		{old: "%%users.userprofile%%\\Application Data", new: "%%users.appdata%%"},
		{old: "%%users.userprofile%%\\Local Settings\\Application Data", new: "%%users.localappdata%%"},
	}
	for _, path := range source.Attributes.Paths {
		for _, deprecation := range deprecations {
			if strings.Contains(path, deprecation.old) {
				r.addInfof(filename, artifactDefinition, "Replace %s by %s", deprecation.old, deprecation.new)
			}
		}
	}
}

// unc (r *validator) validateDoubleStar(filename, artifactDefinition string, source Source) {
// 	for _, path := range source.Attributes.Paths {
// 		if strings.Contains(path, `**`) {
// 			r.addInfof(filename, artifactDefinition, "Paths contains **")
// 			return
// 		}
// 	}
//

func (r *validator) validateNoWindowsHomedir(filename, artifactDefinition string, source artifacts.Source) {
	windowsSource := len(source.SupportedOs) == 1 && source.SupportedOs[0] == supportedOS.Windows
	if len(source.SupportedOs) == 0 || windowsSource {
		for _, path := range source.Attributes.Paths {
			if strings.Contains(path, "%%users.homedir%%") {
				r.addInfof(
					filename, artifactDefinition,
					"Replace %s by %s", "%%users.homedir%%", "%%users.userprofile%%",
				)
			}
		}
	}
}

func (r *validator) validateSourceType(filename, artifactDefinition string, source artifacts.Source) {
	for _, t := range listTypes() {
		if t == source.Type {
			return
		}
	}
	r.addErrorf(filename, artifactDefinition, "Type %s is not valid", source.Type)
}

func (r *validator) validateSourceOS(filename, artifactDefinition string, source artifacts.Source) {
	for _, supportedos := range source.SupportedOs {
		found := false
		for _, os := range listOSS() {
			if os == supportedos {
				found = true
			}
		}
		if !found {
			r.addWarningf(filename, artifactDefinition, "OS %s is not valid", supportedos)
		}
	}
}

func (r *validator) validateParameter(filename, artifactDefinition string, source artifacts.Source) {
	/*
		FindInterpol := func(in string) (string, bool) {
			re := regexp.MustCompile(`%%.*?%%`)
			for _, match := range re.FindAllString(in, -1) {
				match = strings.Trim(match, `%`)
				if _, ok := knowledgeBase[match]; !ok {
					return match, false
				}
			}
			return "", true
		}

		for _, key := range source.Attributes.Keys {
			if match, found := FindInterpol(key); !found {
				r.addWarningf(filename, artifactDefinition, "Parameter %s not found", match)
			}
		}
		for _, keyvalue := range source.Attributes.KeyValuePairs {
			if match, found := FindInterpol(keyvalue.Key); !found {
				r.addWarningf(filename, artifactDefinition, "Parameter %s not found", match)

			}
		}
		for _, path := range source.Attributes.Paths {
			if match, found := FindInterpol(path); !found {
				r.addWarningf(filename, artifactDefinition, "Parameter %s not found", match)

			}
		}

		if match, found := FindInterpol(source.Attributes.Query); !found {
			r.addWarningf(filename, artifactDefinition, "Parameter %s not found", match)
		}
	*/
}

func (r *validator) validateSourceProvides(filename, artifactDefinition string, source artifacts.Source) {
	if (source.Type == artifacts.SourceType.ArtifactGroup || source.Type == artifacts.SourceType.Directory) && len(source.Provides) > 0 {
		r.addWarningf(filename, artifactDefinition, "%s source should not have a provides key", source.Type)
	}
}

func getSupportedOS(definition artifacts.ArtifactDefinition, source artifacts.Source) []string {
	if len(source.SupportedOs) > 0 {
		return source.SupportedOs
	} else if len(definition.SupportedOs) > 0 {
		return definition.SupportedOs
	}
	return listOSS()
}

// supportedOS is an enumeration of all supported OSs.
var supportedOS = struct {
	Darwin  string
	Linux   string
	Windows string
	ESXi    string
}{
	Darwin:  "Darwin",
	Linux:   "Linux",
	Windows: "Windows",
	ESXi:    "ESXi",
}

func listOSS() []string {
	return []string{supportedOS.Darwin, supportedOS.Linux, supportedOS.Windows, supportedOS.ESXi}
}

// listTypes returns a list of all artifact definition source types.
func listTypes() []string {
	return []string{
		artifacts.SourceType.ArtifactGroup,
		artifacts.SourceType.Command,
		artifacts.SourceType.Directory,
		artifacts.SourceType.File,
		artifacts.SourceType.Path,
		artifacts.SourceType.RegistryKey,
		artifacts.SourceType.RegistryValue,
		artifacts.SourceType.Wmi,
	}
}

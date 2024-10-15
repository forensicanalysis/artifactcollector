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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/forensicanalysis/artifactcollector/artifacts"
)

func TestValidator_ValidateFiles(t *testing.T) {
	type args struct {
		yamlfile string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Non existing file", args{"unknown.yaml"}, true},
		{"Valid Artifact Definitions", args{"../../test/artifacts/valid/valid.yaml"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newValidator()
			_, _, err := artifacts.DecodeFile(filepath.FromSlash(tt.args.yamlfile))
			if (err != nil) != tt.wantErr {
				t.Errorf("Validator.ValidateFiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(r.flaws) > 0 {
				t.Errorf("Validator.ValidateFiles() has flaws %v", r.flaws)
			}
		})
	}
}

func TestValidator_ValidateSyntax(t *testing.T) {
	type args struct {
		yamlfile string
	}
	tests := []struct {
		skipOnWindows bool
		name          string
		args          args
		want          []Flaw
	}{
		{true, "Non existing file", args{"unknown.yaml"}, []Flaw{{Error, "Error open unknown.yaml: no such file or directory", "", filepath.FromSlash("unknown.yaml")}}},
		{false, "Comment", args{"../../test/artifacts/invalid/file_3.yaml"}, []Flaw{{Info, "The first line should be a comment", "", filepath.FromSlash("../../test/artifacts/invalid/file_3.yaml")}}},
		{false, "Wrong file ending", args{"../../test/artifacts/invalid/ending.yml"}, []Flaw{{Info, "File should have .yaml ending", "", filepath.FromSlash("../../test/artifacts/invalid/ending.yml")}}},
		{false, "Whitespace at line end", args{"../../test/artifacts/invalid/file_1.yaml"}, []Flaw{{Info, "Line 3 ends with whitespace", "", filepath.FromSlash("../../test/artifacts/invalid/file_1.yaml")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnWindows && (runtime.GOOS == "windows") {
				t.Skip("OS and language specific error message is skipped")
			}
			r := newValidator()
			r.validateSyntax(filepath.FromSlash(tt.args.yamlfile))
			if !flawsEqual(r.flaws, tt.want) {
				t.Errorf("Validator.validateSyntax() = %#v, want %#v", r.flaws, tt.want)
			}
		})
	}
}

func TestValidator_ValidateFilesInvalid(t *testing.T) {
	type test struct {
		name     string
		yamlfile string
	}

	files, err := os.ReadDir(filepath.Join("..", "..", "test", "artifacts", "invalid"))
	if err != nil {
		t.Error(err.Error())
	}
	var tests []test
	for _, file := range files {
		tests = append(tests, test{"Test", filepath.Join("..", "..", "test", "artifacts", "invalid", file.Name())})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newValidator()
			ads, flaws, err := artifacts.DecodeFile(tt.yamlfile)
			if err != nil {
				t.Error(err)
			}

			artifactDefinitionMap := map[string][]artifacts.ArtifactDefinition{
				tt.yamlfile: ads,
			}

			r.validateArtifactDefinitions(artifactDefinitionMap)

			if len(flaws)+len(r.flaws) == 0 {
				t.Errorf("Validator.ValidateFiles() %s has no flaws", tt.yamlfile)
			}
		})
	}
}

func flawsEqual(a, b []Flaw) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Slice(a, func(i, j int) bool {
		return strings.Compare(a[i].Message, a[j].Message) < 0
	})
	sort.Slice(b, func(i, j int) bool {
		return strings.Compare(b[i].Message, b[j].Message) < 0
	})
	return reflect.DeepEqual(a, b)
}

func TestValidator_validateMultipleArtifactDefinitions(t *testing.T) {
	r := newValidator()
	tests := []struct {
		name     string
		fun      func([]artifacts.ArtifactDefinition)
		testfile string
		want     []Flaw
	}{
		{"Duplicate Name", r.validateNameUnique, "name_unique.yaml", []Flaw{{Warning, "Duplicate artifact name Test", "Test", ""}}},
		{"Duplicate Registry Key", r.validateRegistryKeyUnique, "registry_key_unique.yaml", []Flaw{{Warning, "Duplicate registry key foo", "Test", ""}}},
		{"Duplicate Registry Value", r.validateRegistryValueUnique, "registry_value_unique.yaml", []Flaw{{Warning, "Duplicate registry value foo bar", "Test", ""}}},
		{"Cyclic tree", r.validateNoCycles, "no_cycles_1.yaml", []Flaw{{Error, "Cyclic artifact group: [TestA TestB]", "", ""}}},
		{"Selfreference", r.validateNoCycles, "no_cycles_2.yaml", []Flaw{{Error, "Artifact group references itself", "Test", ""}}},
		{"Member does not exist", r.validateGroupMemberExist, "group_member_exist.yaml", []Flaw{{Error, "Unknown name Unknown in Test", "Test", ""}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ads, _, err := artifacts.DecodeFile("../../test/artifacts/invalid/" + tt.testfile)
			if err != nil {
				t.Error(err)
			}
			tt.fun(ads)
			if !flawsEqual(r.flaws, tt.want) {
				t.Errorf("%s() = %v, want %v (%s)", runtime.FuncForPC(reflect.ValueOf(tt.fun).Pointer()).Name(), r.flaws, tt.want, tt.testfile)
			}
			r.flaws = []Flaw{}
		})
	}
}

func TestValidator_validateSingleArtifactDefinitions(t *testing.T) {
	r := newValidator()
	tests := []struct {
		name     string
		fun      func(string, artifacts.ArtifactDefinition)
		testfile string
		want     []Flaw
	}{
		{"Lowercase name", r.validateNameCase, "name_case_1.yaml", []Flaw{{Info, "Artifact names should be CamelCase", "testcommand", "name_case_1.yaml"}}},
		{"Name with whitespace", r.validateNameCase, "name_case_2.yaml", []Flaw{{Info, "Artifact names should not contain whitespace", "Test Command", "name_case_2.yaml"}}},
		{"No sources", r.validateNameTypeSuffix, "name_type_suffix_1.yaml", []Flaw{{Error, "Artifact has no sources", "Test", "name_type_suffix_1.yaml"}}},
		{"No type suffix", r.validateNameTypeSuffix, "name_type_suffix_2.yaml", []Flaw{{Common, "Artifact name should end in Command or Commands", "Test", "name_type_suffix_2.yaml"}}},
		{"Different source types", r.validateNameTypeSuffix, "../valid/name_type_suffix_3.yaml", []Flaw{}},
		{"Doc without empty line", r.validateDocLong, "doc_long.yaml", []Flaw{{Info, "Long docs should contain an empty line", "TestCommand", "doc_long.yaml"}}},
		{"Unknown OS", r.validateArtifactOS, "artifact_os.yaml", []Flaw{{Warning, "OS Unknown is not valid", "UnknownTestCommand", "artifact_os.yaml"}}},
		{"Only /etc", r.validateMacOSDoublePath, "mac_os_double_path_1.yaml", []Flaw{{Warning, "Found /etc but not /private/etc", "TestDirectory", "mac_os_double_path_1.yaml"}}},
		{"Only /private/etc", r.validateMacOSDoublePath, "mac_os_double_path_2.yaml", []Flaw{{Warning, "Found /private/etc but not /etc", "TestDirectory", "mac_os_double_path_2.yaml"}}},
		{"Both paths: /etc and /private/etc", r.validateMacOSDoublePath, "../valid/mac_os_double_path_3.yaml", []Flaw{}},
		{"Both paths: /etc and /private/etc in separate sources", r.validateMacOSDoublePath, "../valid/mac_os_double_path_4.yaml", []Flaw{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ads, _, err := artifacts.DecodeFile(filepath.Join("..", "..", "test", "artifacts", "invalid", filepath.FromSlash(tt.testfile)))
			if err != nil {
				t.Fatalf(err.Error())
			}
			if len(ads) != 1 {
				t.Fatalf("Not exactly one artifact definition in testfile %s", tt.testfile)
			}
			fmt.Println(ads)
			tt.fun(tt.testfile, ads[0])
			if !flawsEqual(r.flaws, tt.want) {
				t.Errorf("%s() = %v, want %v (%s)", runtime.FuncForPC(reflect.ValueOf(tt.fun).Pointer()).Name(), r.flaws, tt.want, tt.testfile)
			}
			r.flaws = []Flaw{}
		})
	}
}

func TestValidator_validateSingleSource(t *testing.T) {
	r := newValidator()
	tests := []struct {
		name     string
		fun      func(string, string, artifacts.Source)
		testfile string
		want     []Flaw
	}{
		{"Misplaced attributes", r.validateUnnessesarryAttributes, "attributes_1.yaml", []Flaw{{Warning, "Unnessesarry attribute set", "Test", "attributes_1.yaml"}}},
		{"Misplaced attributes", r.validateUnnessesarryAttributes, "attributes_2.yaml", []Flaw{{Warning, "Unnessesarry attribute set", "Test", "attributes_2.yaml"}}},
		{"Misplaced attributes", r.validateUnnessesarryAttributes, "attributes_3.yaml", []Flaw{{Warning, "Unnessesarry attribute set", "Test", "attributes_3.yaml"}}},
		{"Misplaced attributes", r.validateUnnessesarryAttributes, "attributes_4.yaml", []Flaw{{Warning, "Unnessesarry attribute set", "Test", "attributes_4.yaml"}}},
		{"Misplaced attributes", r.validateUnnessesarryAttributes, "attributes_5.yaml", []Flaw{{Warning, "Unnessesarry attribute set", "Test", "attributes_5.yaml"}}},
		{"Misplaced attributes", r.validateUnnessesarryAttributes, "attributes_6.yaml", []Flaw{{Warning, "Unnessesarry attribute set", "Test", "attributes_6.yaml"}}},
		{"Misplaced attributes", r.validateUnnessesarryAttributes, "attributes_7.yaml", []Flaw{{Warning, "Unnessesarry attribute set", "Test", "attributes_7.yaml"}}},
		{"Misplaced attributes", r.validateUnnessesarryAttributes, "attributes_8.yaml", []Flaw{{Warning, "Unnessesarry attribute set", "Test", "attributes_8.yaml"}}},
		{"Missing required attribute", r.validateRequiredAttributes, "attributes_9.yaml", []Flaw{{Warning, "An ARTIFACT_GROUP requires the names attribute", "Test", "attributes_9.yaml"}}},
		{"Missing required attribute", r.validateRequiredAttributes, "attributes_10.yaml", []Flaw{{Warning, "A COMMAND requires the cmd attribute", "Test", "attributes_10.yaml"}}},
		{"Missing required attribute", r.validateRequiredWindowsAttributes, "attributes_11.yaml", []Flaw{{Warning, "A DIRECTORY requires the paths attribute", "Test", "attributes_11.yaml"}}},
		{"Missing required attribute", r.validateRequiredWindowsAttributes, "attributes_12.yaml", []Flaw{{Warning, "A FILE requires the paths attribute", "Test", "attributes_12.yaml"}}},
		{"Missing required attribute", r.validateRequiredWindowsAttributes, "attributes_13.yaml", []Flaw{{Warning, "A PATH requires the paths attribute", "Test", "attributes_13.yaml"}}},
		{"Missing required attribute", r.validateRequiredWindowsAttributes, "attributes_14.yaml", []Flaw{{Warning, "A REGISTRY_KEY requires the keys attribute", "Test", "attributes_14.yaml"}}},
		{"Missing required attribute", r.validateRequiredWindowsAttributes, "attributes_15.yaml", []Flaw{{Warning, "A REGISTRY_VALUE requires the key_value_pairs attribute", "Test", "attributes_15.yaml"}}},
		{"Missing required attribute", r.validateRequiredWindowsAttributes, "attributes_16.yaml", []Flaw{{Warning, "A WMI requires the query attribute", "Test", "attributes_16.yaml"}}},
		{"Missing required attribute", r.validateRequiredNonWindowsAttributes, "attributes_11.yaml", []Flaw{{Warning, "A DIRECTORY requires the paths attribute", "Test", "attributes_11.yaml"}}},
		{"Missing required attribute", r.validateRequiredNonWindowsAttributes, "attributes_12.yaml", []Flaw{{Warning, "A FILE requires the paths attribute", "Test", "attributes_12.yaml"}}},
		{"Missing required attribute", r.validateRequiredNonWindowsAttributes, "attributes_13.yaml", []Flaw{{Warning, "A PATH requires the paths attribute", "Test", "attributes_13.yaml"}}},
		{"Missing required attribute", r.validateRequiredNonWindowsAttributes, "attributes_14.yaml", []Flaw{{Error, "REGISTRY_KEY only supported for windows", "Test", "attributes_14.yaml"}}},
		{"Missing required attribute", r.validateRequiredNonWindowsAttributes, "attributes_15.yaml", []Flaw{{Error, "REGISTRY_VALUE only supported for windows", "Test", "attributes_15.yaml"}}},
		{"Missing required attribute", r.validateRequiredNonWindowsAttributes, "attributes_16.yaml", []Flaw{{Error, "WMI only supported for windows", "Test", "attributes_16.yaml"}}},
		{"CURRENT_CONTROL_SET in key", r.validateRegistryCurrentControlSet, "registry_current_control_set_1.yaml", []Flaw{{Info, `Registry key should not start with %CURRENT_CONTROL_SET%. Replace %CURRENT_CONTROL_SET% with HKEY_LOCAL_MACHINE\\System\\CurrentControlSet`, "Test", "registry_current_control_set_1.yaml"}}},
		{"CURRENT_CONTROL_SET in key", r.validateRegistryCurrentControlSet, "registry_current_control_set_2.yaml", []Flaw{{Info, `Registry key should not start with %CURRENT_CONTROL_SET%. Replace %CURRENT_CONTROL_SET% with HKEY_LOCAL_MACHINE\\System\\CurrentControlSet`, "Test", "registry_current_control_set_2.yaml"}}},
		{"HKEYCurrentUser variable", r.validateRegistryHKEYCurrentUser, "registry_hkey_current_user_1.yaml", []Flaw{{Error, `HKEY_CURRENT_USER\\ is not supported instead use: HKEY_USERS\\%users.sid%\\`, "Test", "registry_hkey_current_user_1.yaml"}}},
		{"HKEYCurrentUser variable", r.validateRegistryHKEYCurrentUser, "registry_hkey_current_user_2.yaml", []Flaw{{Error, `HKEY_CURRENT_USER\\ is not supported instead use: HKEY_USERS\\%users.sid%\\`, "Test", "registry_hkey_current_user_2.yaml"}}},
		{"Deprecated variables", r.validateDeprecatedVars, "deprecated_vars.yaml", []Flaw{{Info, `Replace %%users.userprofile%%\AppData\Local by %%users.localappdata%%`, "TestDirectory", "deprecated_vars.yaml"}}},
		// {"** in path", r.validateDoubleStar, "double_star.yaml", []Flaw{{Info, "Paths contains **", "TestFile", "double_star.yaml"}}},
		{"homedir variable on windows", r.validateNoWindowsHomedir, "no_windows_homedir.yaml", []Flaw{{Info, `Replace %%users.homedir%% by %%users.userprofile%%`, "WindowsTestDirectory", "no_windows_homedir.yaml"}}},
		{"Unknown Type", r.validateSourceType, "source_type.yaml", []Flaw{{Error, "Type UNKNOWN is not valid", "TestUnknown", "source_type.yaml"}}},
		{"Unknown OS", r.validateSourceOS, "source_os.yaml", []Flaw{{Warning, "OS Unknown is not valid", "UnknownTestCommand", "source_os.yaml"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ads, _, err := artifacts.DecodeFile(filepath.Join("..", "..", "test", "artifacts", "invalid", tt.testfile))
			if err != nil {
				t.Fatalf(err.Error())
			}
			if len(ads) != 1 {
				t.Fatalf("Not exactly one artifact definition in testfile %s", tt.testfile)
			}
			if len(ads[0].Sources) != 1 {
				t.Fatalf("Not exactly one source in testfile %s", tt.testfile)
			}
			tt.fun(tt.testfile, ads[0].Name, ads[0].Sources[0])
			if !flawsEqual(r.flaws, tt.want) {
				t.Errorf("%s() = %v, want %v (%s)", runtime.FuncForPC(reflect.ValueOf(tt.fun).Pointer()).Name(), r.flaws, tt.want, tt.testfile)
			}
			r.flaws = []Flaw{}
		})
	}
}

func TestValidator_validateNamePrefix(t *testing.T) {
	r := newValidator()

	tests := []struct {
		name     string
		fun      func(string, artifacts.ArtifactDefinition)
		testfile string
		want     []Flaw
	}{
		{"No Linux Prefix", r.validateNamePrefix, "linux_name_prefix_1.yaml", []Flaw{{Common, "Artifact name should start with Linux", "TestCommand", "linux_name_prefix_1.yaml"}}},
		{"No MacOS Prefix", r.validateNamePrefix, "macos_name_prefix_2.yaml", []Flaw{{Common, "Artifact name should start with MacOS", "TestCommand", "macos_name_prefix_2.yaml"}}},
		{"No Windows Prefix", r.validateNamePrefix, "windows_name_prefix_3.yaml", []Flaw{{Common, "Artifact name should start with Windows", "TestCommand", "windows_name_prefix_3.yaml"}}},
		{"Not only windows artifact definition", r.validateOSSpecific, "windows_os_specific_1.yaml", []Flaw{{Info, "File should only contain Windows artifact definitions", "TestCommand", "windows_os_specific_1.yaml"}}},
		{"Not only windows source", r.validateOSSpecific, "windows_os_specific_2.yaml", []Flaw{{Info, "File should only contain Windows artifact definitions", "TestCommand", "windows_os_specific_2.yaml"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ads, _, err := artifacts.DecodeFile(filepath.Join("..", "..", "test", "artifacts", "invalid", tt.testfile))
			if err != nil {
				t.Error(err)
			}
			tt.fun(tt.testfile, ads[0])
			if !flawsEqual(r.flaws, tt.want) {
				t.Errorf("validateNamePrefix() = %v, want %v (%s)", r.flaws, tt.want, tt.testfile)
			}
			r.flaws = []Flaw{}
		})
	}
}

func Test_validator_validateParametersProvided(t *testing.T) {
	r := newValidator()

	tests := []struct {
		name     string
		testfile string
		want     []Flaw
	}{
		{"No provides 1", "not_provided_1.yaml", []Flaw{
			{Warning, "Parameter CURRENT_CONTROL_SET is not provided for Windows", "TestProvided", ""},
			{Warning, "Parameter CURRENT_CONTROL_SET is not provided for Linux", "TestProvided", ""},
			{Warning, "Parameter CURRENT_CONTROL_SET is not provided for Darwin", "TestProvided", ""},
			{Warning, "Parameter CURRENT_CONTROL_SET is not provided for ESXi", "TestProvided", ""},
		}},
		{"No provides 2", "not_provided_2.yaml", []Flaw{
			{Warning, "Parameter CURRENT_CONTROL_SET is not provided for Windows", "TestProvided2", ""},
			{Warning, "Parameter CURRENT_CONTROL_SET is not provided for ESXi", "TestProvided2", ""},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ads, flaws, err := artifacts.DecodeFile(filepath.Join("..", "..", "test", "artifacts", "invalid", tt.testfile))
			if err != nil {
				t.Fatal(err)
			}
			if len(flaws) > 0 {
				t.Fatal(flaws)
			}

			r.validateParametersProvided(ads)

			if !flawsEqual(r.flaws, tt.want) {
				t.Errorf("validateParametersProvided() = %v, want %v (%s)", r.flaws, tt.want, tt.testfile)
			}
			r.flaws = []Flaw{}
		})
	}
}

func Test_validator_validateNoDefinitionProvides(t *testing.T) {
	r := newValidator()

	type args struct {
		filename           string
		artifactDefinition artifacts.ArtifactDefinition
	}
	tests := []struct {
		name string
		args args
		want []Flaw
	}{
		{"defintion provides", args{"foo.yml", artifacts.ArtifactDefinition{Name: "Test", Provides: []string{"foo"}}}, []Flaw{
			{Info, "Definition provides are deprecated", "Test", "foo.yml"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r.validateNoDefinitionProvides(tt.args.filename, tt.args.artifactDefinition)

			if !flawsEqual(r.flaws, tt.want) {
				t.Errorf("validateNoDefinitionProvides() = %v, want %v (%s)", r.flaws, tt.want, tt.args.filename)
			}
			r.flaws = []Flaw{}
		})
	}
}

func Test_validator_validateSourceProvides(t *testing.T) {
	r := newValidator()

	type args struct {
		filename           string
		artifactDefinition string
		source             artifacts.Source
	}
	tests := []struct {
		name string
		args args
		want []Flaw
	}{
		{"defintion provides", args{"foo.yml", "Test", artifacts.Source{Type: "ARTIFACT_GROUP", Provides: []artifacts.Provide{{}}}}, []Flaw{
			{Warning, "ARTIFACT_GROUP source should not have a provides key", "Test", "foo.yml"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r.validateSourceProvides(tt.args.filename, tt.args.artifactDefinition, tt.args.source)

			if !flawsEqual(r.flaws, tt.want) {
				t.Errorf("validateNoDefinitionProvides() = %v, want %v (%s)", r.flaws, tt.want, tt.args.filename)
			}
			r.flaws = []Flaw{}
		})
	}
}

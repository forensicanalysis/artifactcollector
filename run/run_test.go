package run

import (
	"os"
	"strings"
	"testing"

	"github.com/forensicanalysis/artifactcollector/collection"
	"github.com/forensicanalysis/artifactlib/goartifacts"
)

func TestRun(t *testing.T) {
	config := collection.Configuration{Artifacts: []string{"Hostname"}, User: true}
	definitions := []goartifacts.ArtifactDefinition{{
		Name: "Test",
		Sources: []goartifacts.Source{
			{Type: "FILE", Attributes: goartifacts.Attributes{Paths: []string{`C:\Windows\explorer.exe`}}},
			{Type: "PATH", Attributes: goartifacts.Attributes{Paths: []string{`\Program Files`}}},
			{Type: "DIRECTORY", Attributes: goartifacts.Attributes{Paths: []string{`\`}}},
			{Type: "COMMAND", Attributes: goartifacts.Attributes{Cmd: "hostname"}},
			{Type: "REGISTRY_KEY", Attributes: goartifacts.Attributes{Keys: []string{`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Time Zones\*`}}},
			{Type: "REGISTRY_VALUE", Attributes: goartifacts.Attributes{KeyValuePairs: []goartifacts.KeyValuePair{{Key: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Nls\CodePage`, Value: "ACP"}}}},
			{Type: "WMI", Attributes: goartifacts.Attributes{Query: "SELECT LastBootUpTime FROM Win32_OperatingSystem"}},
		},
	}}

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		config              *collection.Configuration
		artifactDefinitions []goartifacts.ArtifactDefinition
		embedded            map[string][]byte
	}
	tests := []struct {
		name     string
		args     args
		wantHost string
	}{
		{"Run artifactcollector", args{&config, definitions, nil}, hostname},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Run(tt.args.config, tt.args.artifactDefinitions, tt.args.embedded)

			if !strings.HasPrefix(got.Name, tt.wantHost) {
				t.Errorf("Run().Name = %v, does not start with %v", got, tt.wantHost)
			}

			if !strings.HasPrefix(got.Path, tt.wantHost) {
				t.Errorf("Run().Path = %v, does not start with %v", got, tt.wantHost)
			}

			if _, err := os.Stat(got.Path); os.IsNotExist(err) {
				t.Errorf("Returned path %s does not exist", got.Path)
			}
			if _, err := os.Stat(strings.Replace(got.Path, ".forensicstore.zip", ".log", 1)); os.IsNotExist(err) {
				t.Errorf("Log file %s does not exist", strings.Replace(got.Path, ".zip", ".log", 1))
			}
		})
	}
}

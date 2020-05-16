package assets

import (
	"github.com/forensicanalysis/artifactcollector/collection"
	"github.com/spf13/afero"
)

var Config = &collection.Configuration{Artifacts: []string{"DefaultEntryPoint"}, User: false, Case: "", OutputDir: "", FS: afero.Fs(nil)}

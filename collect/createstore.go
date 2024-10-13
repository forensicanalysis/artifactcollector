package collect

import (
	"log"
	"os"

	"github.com/forensicanalysis/artifactcollector/artifacts"
	"github.com/forensicanalysis/artifactcollector/collector"
	"github.com/forensicanalysis/artifactcollector/store"
)

func createStore(storePath string, config *collector.Configuration, definitions []artifacts.ArtifactDefinition) (*store.ZipStore, func() error, error) {
	f, err := os.Create(storePath)
	if err != nil {
		log.Fatal(err)
	}

	store := store.NewSimpleStore(f)
	teardown := func() error {
		if err := store.Close(); err != nil {
			return err
		}

		return f.Close()
	}

	if err := store.InsertStruct("definitions", definitions); err != nil {
		return nil, nil, err
	}

	if err := store.InsertStruct("artifacts", config.Artifacts); err != nil {
		return nil, nil, err
	}

	return store, teardown, nil
}

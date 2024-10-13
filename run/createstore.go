package run

import (
	"fmt"
	"log"
	"os"

	"github.com/forensicanalysis/artifactlib/goartifacts"

	"github.com/forensicanalysis/artifactcollector/collection"
	"github.com/forensicanalysis/artifactcollector/store"
)

func createStore(collectionName string, config *collection.Configuration, definitions []goartifacts.ArtifactDefinition) (string, *store.SimpleStore, func() error, error) {
	storeName := fmt.Sprintf("%s.zip", collectionName)

	f, err := os.Create(storeName)
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

	if err := store.InsertStruct(definitions); err != nil {
		return "", nil, nil, err
	}

	if err := store.InsertStruct(config.Artifacts); err != nil {
		return "", nil, nil, err
	}

	return storeName, store, teardown, nil
}

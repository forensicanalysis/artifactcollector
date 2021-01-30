// +build !go1.7

package run

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"github.com/forensicanalysis/artifactcollector/collection"
	"github.com/forensicanalysis/artifactcollector/zipwrite"
	"github.com/forensicanalysis/artifactlib/goartifacts"
)

func createStore(collectionName string, config *collection.Configuration, definitions []goartifacts.ArtifactDefinition) (string, collection.Store, func() error, error) {
	storeName := fmt.Sprintf("%s.json", collectionName)

	f, err := os.Create("collection.zip")
	if err != nil {
		log.Fatal(err)
	}
	fs := zipwrite.New(f)
	store := simpleStore{
		buffer: &bytes.Buffer{},
		Fs:     fs,
	}
	teardown := func() error {
		_ = store.Close()
		_ = fs.Close()
		return f.Close()
	}

	return storeName, store, teardown, nil
}

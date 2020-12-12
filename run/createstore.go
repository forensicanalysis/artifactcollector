// +build go1.7

package run

import (
	"crawshaw.io/sqlite"
	"encoding/json"
	"fmt"
	"log"

	"github.com/forensicanalysis/artifactcollector/collection"
	"github.com/forensicanalysis/artifactlib/goartifacts"
	"github.com/forensicanalysis/forensicstore"
)

func createStore(collectionName string, config *collection.Configuration, definitions []goartifacts.ArtifactDefinition) (string, collection.Store, func() error, error) {
	storeName := fmt.Sprintf("%s.forensicstore", collectionName)
	store, teardown, err := forensicstore.New(storeName)
	if err != nil {
		return "", nil, teardown, err
	}

	_, err = store.Query(`CREATE TABLE IF NOT EXISTS config (
		key TEXT NOT NULL,
		value TEXT
	);`)
	if err != nil {
		return "", nil, teardown, err
	}

	conn := store.Connection()

	// insert configuration into store
	err = addConfig(conn, "config", config)
	if err != nil {
		log.Println(err)
	}

	// insert artifact definitions into store
	for _, artifact := range definitions {
		err = addConfig(conn, "artifact:"+artifact.Name, artifact)
		if err != nil {
			log.Println(err)
		}
	}

	return storeName, store, teardown, nil
}

func addConfig(conn *sqlite.Conn, key string, value interface{}) error {
	stmt, err := conn.Prepare("INSERT INTO `config` (key, value) VALUES ($key, $value)")
	if err != nil {
		return err
	}

	b, err := json.Marshal(value)
	if err != nil {
		return err
	}

	stmt.SetText("$key", key)
	stmt.SetText("$value", string(b))

	_, err = stmt.Step()
	if err != nil {
		return err
	}

	return stmt.Finalize()
}

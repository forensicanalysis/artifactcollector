package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/forensicanalysis/artifactcollector/store/aczip"
)

type SimpleStore struct {
	w *aczip.Writer
}

func NewSimpleStore(f *os.File) *SimpleStore {
	return &SimpleStore{
		w: aczip.NewWriter(f),
	}
}

func (k *SimpleStore) InsertStruct(element interface{}) error {
	b, err := json.Marshal(element)
	if err != nil {
		return err
	}

	uid := uuid.New()

	if _, err := k.w.WriteFile("artifacts/"+uid.String()+".json", b); err != nil {
		return err
	}

	return nil
}

func (k *SimpleStore) StoreFile(filePath string) (storePath string, file io.Writer, err error) {
	filePath = "files/" + filePath

	i := 0
	ext := filepath.Ext(filePath)
	remoteStoreFilePath := filePath
	base := remoteStoreFilePath[:len(remoteStoreFilePath)-len(ext)]

	exists, err := k.w.Exists(remoteStoreFilePath)
	if err != nil {
		return "", nil, err
	}

	for exists {
		remoteStoreFilePath = fmt.Sprintf("%s_%d%s", base, i, ext)
		i++

		exists, err = k.w.Exists(remoteStoreFilePath)
		if err != nil {
			return "", nil, err
		}
	}

	file, err = k.w.Create(remoteStoreFilePath)

	return remoteStoreFilePath, file, err
}

func (k *SimpleStore) LoadFile(filePath string) (file io.Reader, err error) {
	b, err := k.w.Read(filePath)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(b), nil
}

func (k *SimpleStore) Log(name, msg string) error {
	_, err := k.w.WriteFile("logs/"+name+".log", []byte(msg))

	return err
}

func (k *SimpleStore) Close() error {
	return k.w.Close()
}

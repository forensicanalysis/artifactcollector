package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/forensicanalysis/artifactcollector/store/aczip"
)

type ZipStore struct {
	w *aczip.Writer
}

func NewSimpleStore(f *os.File) *ZipStore {
	return &ZipStore{
		w: aczip.NewWriter(f),
	}
}

func (k *ZipStore) InsertStruct(artifact, id string, element interface{}) error {
	b, err := json.Marshal(element)
	if err != nil {
		return err
	}

	_, err = k.w.WriteFile(fmt.Sprintf("artifacts/%s/%s.json", artifact, id), b)

	return err
}

func (k *ZipStore) StoreFile(filePath string) (storePath string, file io.Writer, err error) {
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

func (k *ZipStore) LoadFile(filePath string) (file io.Reader, err error) {
	b, err := k.w.Read(filePath)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(b), nil
}

func (k *ZipStore) Write(b []byte) (int, error) {
	name := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)

	return k.w.WriteFile("logs/"+name+".log", b)
}

func (k *ZipStore) Close() error {
	return k.w.Close()
}

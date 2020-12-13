package run

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"

	"github.com/fatih/structs"
	"github.com/spf13/afero"
	"github.com/stoewer/go-strcase"
)

type simpleStore struct {
	buffer *bytes.Buffer
	Fs     afero.Fs
}

func (k simpleStore) SetFS(fs afero.Fs) {
	k.Fs = fs
}

func (k simpleStore) InsertStruct(element interface{}) (string, error) {
	m := structs.Map(element)
	m = lower(m).(map[string]interface{})
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	_, err = k.buffer.Write(b)
	return string(b), err
}

func (k simpleStore) StoreFile(filePath string) (storePath string, file io.WriteCloser, teardown func() error, err error) {
	err = k.Fs.MkdirAll(filepath.Dir(filePath), 0755)
	if err != nil {
		return "", nil, nil, err
	}

	i := 0
	ext := filepath.Ext(filePath)
	remoteStoreFilePath := filePath
	base := remoteStoreFilePath[:len(remoteStoreFilePath)-len(ext)]

	exists, err := afero.Exists(k.Fs, remoteStoreFilePath)
	if err != nil {
		return "", nil, nil, err
	}
	for exists {
		remoteStoreFilePath = fmt.Sprintf("%s_%d%s", base, i, ext)
		i++
		exists, err = afero.Exists(k.Fs, remoteStoreFilePath)
		if err != nil {
			return "", nil, nil, err
		}
	}

	file, err = k.Fs.Create(remoteStoreFilePath)
	return remoteStoreFilePath, file, file.Close, err
}

func (k simpleStore) LoadFile(filePath string) (file io.ReadCloser, teardown func() error, err error) {
	file, err = k.Fs.Open(filePath)
	return file, file.Close, err
}

func (k simpleStore) Close() error {
	_, f, close, err := k.StoreFile("collection.json")
	if err != nil {
		return err
	}
	_, err = io.Copy(f, k.buffer)
	if err != nil {
		return err
	}
	return close()
}

func lower(f interface{}) interface{} {
	var hashes = map[string]bool{
		"MD5":        true,
		"MD6":        true,
		"RIPEMD-160": true,
		"SHA-1":      true,
		"SHA-224":    true,
		"SHA-256":    true,
		"SHA-384":    true,
		"SHA-512":    true,
		"SHA3-224":   true,
		"SHA3-256":   true,
		"SHA3-384":   true,
		"SHA3-512":   true,
		"SSDEEP":     true,
		"WHIRLPOOL":  true,
	}
	switch f := f.(type) {
	case []interface{}:
		for i := range f {
			if !isEmptyValue(reflect.ValueOf(f[i])) {
				f[i] = lower(f[i])
			}
		}
		return f
	case map[string]interface{}:
		lf := make(map[string]interface{}, len(f))
		for k, v := range f {
			if !isEmptyValue(reflect.ValueOf(v)) {
				if _, ok := hashes[k]; ok {
					lf[k] = lower(v)
				} else {
					lf[strcase.SnakeCase(k)] = lower(v)
				}
			}
		}
		return lf
	default:
		return f
	}
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

// Code generated by github.com/cugu/go-resources. DO NOT EDIT.

package assets

type FileSystem struct {
	Files map[string][]byte
}

var FS *FileSystem

func init() {
	FS = &FileSystem{
		Files: map[string][]byte{},
	}
}

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/forensicanalysis/go-resources/testdata/generated"
)

//go:generate go build -o testdata/resources .
//go:generate testdata/resources -package generated -output testdata/generated/store_prod.go  testdata/*.txt testdata/*.sql testdata/*.bin

func TestGenerated(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
	}{
		{name: "test.txt"},
		{name: "patrick.txt"},
		{name: "query.sql"},
		{name: "123.bin"},
		{name: "12.bin"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, ok := generated.FS["/testdata/"+tt.name]

			if !ok {
				t.Fatalf("expected no error opening file")
			}

			data, err := os.ReadFile(filepath.Join("testdata", tt.name))
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(content, data) {
				t.Errorf("expected to find snippet '%x', got: '%x'", data, content)
			}
		})
	}
}

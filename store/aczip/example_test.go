// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aczip_test

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/forensicanalysis/artifactcollector/store/aczip"
)

func ExampleWriter() {
	// Create a buffer to write our archive to.
	f, err := os.CreateTemp("", "test.zip")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new zip archive.
	w := aczip.NewWriter(f)

	// Add some files to the archive.
	files := []struct {
		Name, Body string
	}{
		{"readme.txt", "This archive contains some text files."},
		{"gopher.txt", "Gopher names:\nGeorge\nGeoffrey\nGonzo"},
		{"todo.txt", "Get animal handling licence.\nWrite more examples."},
	}
	for _, file := range files {
		f, err := w.Create(file.Name)
		if err != nil {
			log.Fatal(err)
		}

		_, err = f.Write([]byte(file.Body))
		if err != nil {
			log.Fatal(err)
		}
	}

	// Make sure to check the error on Close.
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
}

func ExampleReader() {
	// Open a zip archive for reading.
	r, err := zip.OpenReader("testdata/readme.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	// Iterate through the files in the archive,
	// printing some of their contents.
	for _, f := range r.File {
		fmt.Printf("Contents of %s:\n", f.Name)

		rc, err := f.Open()
		if err != nil {
			log.Fatal(err)
		}

		_, err = io.CopyN(os.Stdout, rc, 68)
		if err != nil {
			log.Fatal(err)
		}

		rc.Close()
		fmt.Println()
	}
	// Output:
	// Contents of README:
	// This is the source code repository for the Go programming language.
}

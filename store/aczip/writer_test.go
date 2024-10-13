// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aczip

import (
	"archive/zip"
	"bytes"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
)

type WriteTest struct {
	Name string
	Data []byte
	Mode os.FileMode
}

var writeTests = []WriteTest{
	{
		Name: "foo",
		Data: []byte("Rabbits, guinea pigs, gophers, marsupial rats, and quolls."),
		Mode: 0o666,
	},
	{
		Name: "bar",
		Data: nil, // large data set in the test
		Mode: 0o644,
	},
	{
		Name: "setuid",
		Data: []byte("setuid file"),
		Mode: 0o755 | os.ModeSetuid,
	},
	{
		Name: "setgid",
		Data: []byte("setgid file"),
		Mode: 0o755 | os.ModeSetgid,
	},
	{
		Name: "symlink",
		Data: []byte("../link/target"),
		Mode: 0o755 | os.ModeSymlink,
	},
}

func TestWriter(t *testing.T) {
	largeData := make([]byte, 1<<17)
	for i := range largeData {
		largeData[i] = byte(rand.Int())
	}

	writeTests[1].Data = largeData

	defer func() {
		writeTests[1].Data = nil
	}()

	// write a zip file
	f, err := os.CreateTemp("", "test.zip")
	if err != nil {
		t.Fatal(err)
	}
	// defer os.Remove(f.Name())
	w := NewWriter(f)

	for _, wt := range writeTests {
		testCreate(t, w, &wt)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Log(f.Name())

	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}

	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}

	// read it back
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}

	for i, wt := range writeTests {
		testReadFile(t, r.File[i], &wt)
	}
}

func testCreate(t *testing.T, w *Writer, wt *WriteTest) {
	header := &zip.FileHeader{
		Name:   wt.Name,
		Method: Deflate,
	}
	if wt.Mode != 0 {
		header.SetMode(wt.Mode)
	}

	f, err := w.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write(wt.Data)
	if err != nil {
		t.Fatal(err)
	}
}

func testReadFile(t *testing.T, f *zip.File, wt *WriteTest) {
	if f.Name != wt.Name {
		t.Fatalf("File name: got %q, want %q", f.Name, wt.Name)
	}

	testFileMode(t, wt.Name, f, wt.Mode)

	rc, err := f.Open()
	if err != nil {
		t.Fatal("opening:", err)
	}

	b, err := ioutil.ReadAll(rc)
	if err != nil {
		t.Fatal("reading:", err)
	}

	err = rc.Close()
	if err != nil {
		t.Fatal("closing:", err)
	}

	if !bytes.Equal(b, wt.Data) {
		t.Errorf("File contents %q, want %q", b, wt.Data)
	}
}

func testFileMode(t *testing.T, zipName string, f *zip.File, want os.FileMode) {
	mode := f.Mode()
	if want == 0 {
		t.Errorf("%s: %s mode: got %v, want none", zipName, f.Name, mode)
	} else if mode != want {
		t.Errorf("%s: %s mode: want %v, got %v", zipName, f.Name, want, mode)
	}
}

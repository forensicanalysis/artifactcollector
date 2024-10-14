package aczip_test

import (
	"log"
	"os"
	"testing"

	"github.com/forensicanalysis/artifactcollector/store/aczip"
)

func TestRead(t *testing.T) {
	f, err := os.CreateTemp("", "test.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	w := aczip.NewWriter(f)

	_, err = w.Create("test.txt")
	if err != nil {
		t.Fatal(err)
	}

	zf, err := w.Create("test2.txt")
	if err != nil {
		t.Fatal(err)
	}

	_, err = zf.Write([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	read, err := w.Read("test.txt")
	if err != nil {
		t.Fatal(err)
	}

	if string(read) != "" {
		t.Fatalf("read is not empty: %s", read)
	}

	read, err = w.Read("test2.txt")
	if err != nil {
		t.Fatal(err)
	}

	log.Println(f.Name())

	if string(read) != "test" {
		t.Fatalf("read is not test: %s", read)
	}

	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}
}

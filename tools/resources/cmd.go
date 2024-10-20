// Unfancy resources embedding with Go.

package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	pkgName  = "main"
	varName  = "FS"
	tag      = ""
	out      = ""
	trimPath = ""
)

type nope struct{}

func main() {
	t0 := time.Now()

	flag.StringVar(&pkgName, "package", pkgName, "`name` of the package to generate")
	flag.StringVar(&varName, "var", varName, "`name` of the variable to assign the virtual filesystem to")
	flag.StringVar(&tag, "tag", tag, "`tag` to use for the generated package (default no tag)")
	flag.StringVar(&out, "output", out, "`filename` to write the output to")
	flag.StringVar(&trimPath, "trim", trimPath, "path `prefix` to remove from the resulting file path in the virtual filesystem")
	flag.Parse()

	if out == "" {
		flag.PrintDefaults()
		log.Fatal("-output is required.")
	}

	config := Config{
		Pkg: pkgName,
		Var: varName,
		Tag: tag,
	}

	res := New()
	res.Config = config

	files := make(map[string]nope)

	for _, g := range flag.Args() {
		matches, err := filepath.Glob(g)
		if err != nil {
			log.Fatal(err)
		}

		for _, m := range matches {
			info, err := os.Stat(m)

			if !os.IsNotExist(err) && !info.IsDir() {
				files[m] = nope{}
			}
		}
	}

	for path := range files {
		name := filepath.ToSlash(path)
		name = strings.TrimPrefix(name, trimPath)

		err := res.AddFile(name, path)
		if err != nil {
			log.Fatal(err)
		}
	}

	if err := res.Write(out); err != nil {
		log.Fatal(err)
	}

	log.Printf("Finished in %v. Wrote %d resources to %s", time.Since(t0), len(files), out)
}

package doublestar_test

import (
	"fmt"
	"os"

	"github.com/forensicanalysis/artifactcollector/doublestar"
)

func Example() {
	// get file system for this repository
	wd, _ := os.Getwd()
	fsys := os.DirFS(wd)

	// get all yml files
	matches, _ := doublestar.Glob(fsys, "**/*.md")

	// print matches
	fmt.Println(matches)
	// Output: [README.md]
}

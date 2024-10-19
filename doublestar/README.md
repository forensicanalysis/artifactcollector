Recursive directory globbing via `**` for Go's [io/fs](https://golang.org/pkg/io/fs).

## Example

``` golang
func main() {
	// get file system for this repository
	wd, _ := os.Getwd()
	fsys := os.DirFS(wd)

	// get all yml files
	matches, _ := fsdoublestar.Glob(fsys, "**/*.yml")

	// print matches
	fmt.Println(matches)
	// Output: [.github/workflows/ci.yml .github/.golangci.yml]
}
```

## Acknowledgement

This repository is based on [Bob Matcuk's](https://github.com/bmatcuk) great [doublestar](https://github.com/bmatcuk/doublestar) package.

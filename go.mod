module github.com/forensicanalysis/artifactcollector

go 1.13

require (
	github.com/cheggaaa/pb/v3 v3.0.2
	github.com/forensicanalysis/artifactlib v0.12.2
	github.com/forensicanalysis/forensicstore v0.12.2
	github.com/forensicanalysis/fslib v0.12.1
	github.com/go-ole/go-ole v1.2.4
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/pkg/errors v0.8.1
	github.com/spf13/afero v1.2.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/sys v0.0.0-20191113165036-4c7a9d0fe056
)

replace github.com/forensicanalysis/artifactlib => ../artifactlib

module github.com/forensicanalysis/artifactcollector/scripts

go 1.13

require (
	github.com/forensicanalysis/artifactcollector v0.12.1
	github.com/forensicanalysis/artifactlib v0.13.2
	github.com/pkg/errors v0.9.1
	gopkg.in/yaml.v2 v2.2.8
)

replace github.com/forensicanalysis/artifactcollector => ../

package collect

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/forensicanalysis/artifactcollector/collector"
)

// Run is the output of a run that can be used to further process the output
// (e.g. send the output to a SFTP server).
type Run struct {
	Name        string
	StorePath   string
	LogfilePath string
}

func NewRun(config *collector.Configuration) *Run {
	var outputDirFlag string

	flag.StringVar(&outputDirFlag, "o", "", "Output directory for forensicstore and log file")
	flag.Parse()

	cwd, _ := os.Getwd()

	outputDir := "" // current directory

	// output dir order:
	// 1. -o flag given
	// 2. implemented in config
	// 3.1. running from zip -> Desktop
	// 3.2. otherwise -> current directory
	switch {
	case outputDirFlag != "":
		outputDir = outputDirFlag
	case config.OutputDir != "":
		outputDir = config.OutputDir
	case windowsZipTempDir.MatchString(cwd) || sevenZipTempDir.MatchString(cwd):
		fmt.Println("Running from zip, results will be available on Desktop")

		outputDir = filepath.Join(homeDir(), "Desktop")
	}

	if outputDir != "" {
		_ = os.MkdirAll(outputDir, 0700)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "artifactcollector"
	}

	if config.Case != "" {
		hostname = config.Case + "-" + hostname
	}

	t := time.Now().UTC().Format("2006-01-02T15-04-05")
	collectionName := fmt.Sprintf("%s_%s", hostname, t)

	return &Run{
		Name:        collectionName,
		LogfilePath: filepath.Join(outputDir, collectionName+".log"),
		StorePath:   filepath.Join(outputDir, collectionName+".zip"),
	}
}

func homeDir() string {
	if runtime.GOOS == "windows" {
		os.Getenv("USERPROFILE")
	}

	return os.Getenv("HOME")
}

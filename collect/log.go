package collect

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var logfile *os.File

func setupLogging(logfilePath string) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var err error

	logfile, err = os.OpenFile(logfilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("Could not open logfile %s\n", err)
	} else {
		log.SetOutput(logfile)
	}
}

func addLogger(w io.Writer) {
	if logfile != nil {
		log.SetOutput(io.MultiWriter(logfile, w))
	} else {
		log.SetOutput(w)
	}
}

func resetLogger() {
	if logfile != nil {
		log.SetOutput(logfile)
	} else {
		log.SetOutput(ioutil.Discard)
	}
}

func closeLogging() error {
	if logfile != nil {
		log.SetOutput(ioutil.Discard)

		return logfile.Close()
	}

	return nil
}

func logPrint(a ...interface{}) {
	log.Println(a...)
	fmt.Println(a...)
}

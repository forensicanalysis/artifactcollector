// Copyright (c) 2019 Siemens AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Author(s): Jonas Plum

package collection

import (
	"crypto/md5"  // #nosec
	"crypto/sha1" // #nosec
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/forensicanalysis/fslib/systemfs"
)

func getString(m map[string]interface{}, key string) string {
	if value, ok := m[key]; ok {
		if valueString, ok := value.(string); ok {
			return valueString
		}
	}
	return ""
}

func (c *LiveCollector) createFile(definitionName string, collectContents bool, srcpath, _ string) (f *File) { //nolint:funlen,gocyclo,gocognit
	file := NewFile()
	file.Artifact = definitionName
	file.Name = path.Base(srcpath)
	file.Origin = map[string]interface{}{"path": srcpath}

	if !strings.Contains(srcpath, "*") && !strings.Contains(srcpath, "%%") { //nolint: nestif
		// exists
		srcInfo, err := fs.Stat(c.SourceFS, srcpath)
		if err != nil {
			if os.IsNotExist(err) || strings.Contains(strings.ToLower(err.Error()), "not found") {
				return nil
			}
			return file.AddError(err.Error())
		}

		// do not return dirs
		if srcInfo.IsDir() && collectContents {
			return nil
		}

		file.Size = float64(srcInfo.Size())
		attr := srcInfo.Sys()
		if attributes, ok := attr.(map[string]interface{}); ok {
			file.Ctime = getString(attributes, "created")
			file.Mtime = getString(attributes, "modified")
			file.Atime = getString(attributes, "accessed")
			delete(attributes, "created")
			delete(attributes, "modified")
			delete(attributes, "accessed")
			file.Attributes = attributes
			file.Attributes["stat_size"] = srcInfo.Size()
		} else {
			file.Attributes = map[string]interface{}{"stat_size": srcInfo.Size()}
		}

		// copy file
		if collectContents && file.Size > 0 {
			hostname, err := os.Hostname()
			if err != nil {
				hostname = ""
			}
			dstpath, storeFile, storeFileTeardown, err := c.Store.StoreFile(filepath.Join(hostname, strings.TrimLeft(srcpath, "")))
			if err != nil {
				return file.AddError(fmt.Errorf("error storing file: %w", err).Error())
			}
			defer func() {
				// this writes the file to the database
				if err := storeFileTeardown(); err != nil {
					f = file.AddError(fmt.Errorf("write error: %w", err).Error())
				}
			}()

			srcFile, err := c.SourceFS.Open(srcpath)
			if err != nil {
				return file.AddError(fmt.Errorf("error opening file: %w", err).Error())
			}

			size, hashes, err := hashCopy(storeFile, srcFile)

			if cerr := srcFile.Close(); cerr != nil {
				log.Println(cerr)
			}

			if err != nil {
				// Copy failed, try NTFS copy
				// is a lock violation
				errorLockViolation := 33
				if systemFS, ok := c.SourceFS.(*systemfs.FS); ok {
					if errno, ok := err.(syscall.Errno); ok && int(errno) == errorLockViolation {
						log.Println("copy error because of a lock violation, try low level copy")

						ntfsSrcFile, teardown, oerr := systemFS.NTFSOpen(srcpath)
						if oerr != nil {
							return file.AddError(fmt.Errorf("error opening NTFS file: %w", oerr).Error())
						}
						defer func() {
							if terr := teardown(); terr != nil {
								log.Println(terr)
							}
						}()

						// reset file or open a new store file
						if !resetFile(storeFile) {
							if err := storeFile.Close(); err != nil {
								log.Println(err)
							}
							dstpath, storeFile, storeFileTeardown, err = c.Store.StoreFile(filepath.Join(hostname, strings.TrimLeft(srcpath, "")))
							if err != nil {
								return file.AddError(fmt.Errorf("error storing file: %w", err).Error())
							}
						}

						size, hashes, err = hashCopy(storeFile, ntfsSrcFile)
					}
				}
				if err != nil {
					return file.AddError(fmt.Errorf("copy error %T %s -> store %s: %w", c.SourceFS, srcpath, dstpath, err).Error())
				}
			}
			if size != srcInfo.Size() {
				file.AddError(fmt.Sprintf("filesize parsed is %d, copied %d bytes", srcInfo.Size(), size))
			}

			file.Size = float64(size)
			file.ExportPath = filepath.ToSlash(dstpath)
			file.Hashes = hashes
		}
		return file
	}
	return file.AddError("path contains unknown expanders")
}

type Resetter interface {
	Reset()
}

func resetFile(storeFile io.WriteCloser) bool {
	reset := false
	if seeker, ok := storeFile.(io.Seeker); ok {
		_, err := seeker.Seek(0, os.SEEK_CUR)
		if err != nil {
			reset = true
		}
	}
	if resetter, ok := storeFile.(Resetter); ok {
		resetter.Reset()
		reset = true
	}
	return reset
}

func hashCopy(dst io.Writer, src io.Reader) (int64, map[string]interface{}, error) {
	md5hash, sha1hash, sha256hash := md5.New(), sha1.New(), sha256.New() // #nosec
	size, err := io.Copy(io.MultiWriter(dst, sha1hash, md5hash, sha256hash), src)
	if err != nil {
		return 0, nil, err
	}
	return size, map[string]interface{}{
		"MD5":     fmt.Sprintf("%x", md5hash.Sum(nil)),
		"SHA-1":   fmt.Sprintf("%x", sha1hash.Sum(nil)),
		"SHA-256": fmt.Sprintf("%x", sha256hash.Sum(nil)),
	}, nil
}

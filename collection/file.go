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
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/forensicanalysis/forensicstore/goforensicstore"
	"github.com/forensicanalysis/fslib"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
)

func (c *Collector) createFile(definitionName string, collectContents bool, srcpath, dstdir string) *goforensicstore.File {
	file := &goforensicstore.File{}
	file.Artifact = definitionName
	file.Type = "file"
	file.Name = path.Base(srcpath)
	file.Origin = map[string]interface{}{"path": srcpath}

	if !strings.Contains(srcpath, "*") && !strings.Contains(srcpath, "%%") {
		// exists
		srcInfo, err := c.SourceFS.Stat(srcpath)
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

		if m, ok := attr.(map[string]interface{}); ok {
			if created, ok := m["created"]; ok {
				if createdString, ok := created.(string); ok {
					file.Created = createdString
				}
			}
			if modified, ok := m["modified"]; ok {
				if modifiedString, ok := modified.(string); ok {
					file.Modified = modifiedString
				}
			}
			if accessed, ok := m["accessed"]; ok {
				if accessedString, ok := accessed.(string); ok {
					file.Accessed = accessedString
				}
			}
			file.Attributes = m
		}

		// copy file
		if collectContents && file.Size > 0 {
			dstpath, storeFile, err := c.Store.StoreFile(filepath.Join(dstdir, path.Base(srcpath)))
			if err != nil {
				return file.AddError(errors.Wrap(err, "error storing file").Error())
			}
			defer storeFile.Close()

			srcFile, err := c.SourceFS.Open(srcpath)
			if err != nil {
				return file.AddError(errors.Wrap(err, "error openung file").Error())
			}
			defer srcFile.Close()

			size, hashes, err := hashCopyFile(srcFile, storeFile)
			if err != nil {
				errorMessage := fmt.Sprintf("copy error %s %s -> %s %s", c.SourceFS.Name(), srcpath, c.Store.Name(), dstpath)
				return file.AddError(errors.Wrap(err, errorMessage).Error())
			}
			if size != srcInfo.Size() {
				file.AddError(fmt.Sprintf("filesize parsed is %d, copied %d bytes", srcInfo.Size(), size))
			}

			file.ExportPath = filepath.ToSlash(dstpath)
			file.Hashes = map[string]interface{}{
				"SHA-1": fmt.Sprintf("%x", hashes["SHA-1"]),
				"MD5":   fmt.Sprintf("%x", hashes["MD5"]),
			}
			return file
		}

		return file
	}
	return file.AddError("path contains unknown expanders")
}

func hashCopyFile(srcfile fslib.Item, destfile afero.File) (int64, map[string][]byte, error) {
	sha1hash := sha1.New() // #nosec
	md5hash := md5.New()   // #nosec
	size, err := io.Copy(io.MultiWriter(destfile, sha1hash, md5hash), srcfile)
	return size, map[string][]byte{"MD5": md5hash.Sum(nil), "SHA-1": sha1hash.Sum(nil)}, errors.Wrap(err, "copy failed")
}

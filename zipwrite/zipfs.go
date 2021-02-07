// Copyright (c) 2020 Siemens AG
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

// Package zipwrite provides good enough write-only file system implementation for
// the artifactcollector to create zip files.
package zipwrite

import (
	"archive/zip"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/afero"
)

// FS implements a write-only file system for zip files.
type FS struct {
	zipwriter *zip.Writer
	files     map[string]bool
}

// New creates a new zipwrite FS.
func New(writer io.Writer) *FS {
	return &FS{
		zipwriter: zip.NewWriter(writer),
		files:     map[string]bool{},
	}
}

// Create creates a file in the filesystem, returning the file and an
// error, if any happens.
func (fs *FS) Create(name string) (afero.File, error) {
	filewriter, err := fs.zipwriter.Create(name)
	if err != nil {
		return nil, err
	}
	return Item{name, filewriter}, nil
}

// Mkdir creates a directory in the filesystem, return an error if any
// happens.
func (fs *FS) Mkdir(name string, perm os.FileMode) error {
	_, err := fs.zipwriter.Create(name + "/")
	return err
}

// MkdirAll creates a directory path and all parents that does not exist
// yet.
func (fs *FS) MkdirAll(path string, perm os.FileMode) error {
	return fs.Mkdir(path, perm)
}

// Open opens a file, returning it or an error, if any happens.
func (fs *FS) Open(name string) (afero.File, error) {
	return nil, errors.Wrap(syscall.EPERM, "open: ZIP filesystem is in write mode")
}

// OpenFile opens a file using the given flags and the given mode.
func (fs *FS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if flag&(os.O_WRONLY|syscall.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
		return fs.Create(name)
	}

	return nil, errors.Wrap(syscall.EPERM, "openfile: ZIP filesystem is in write mode")
}

// Remove removes a file identified by name, returning an error, if any happens.
func (fs *FS) Remove(name string) error {
	return errors.New("Remove not implemented")
}

// RemoveAll removes a directory path and any children it contains. It
// does not fail if the path does not exist (return nil).
func (fs *FS) RemoveAll(path string) error {
	return errors.New("RemoveAll not implemented")
}

// Rename renames a file.
func (fs *FS) Rename(oldname, newname string) error {
	return errors.New("Rename not implemented")
}

// Stat returns a RootInfo describing the named file, or an error, if any
// happens.
func (fs *FS) Stat(name string) (os.FileInfo, error) {
	if _, ok := fs.files[name]; !ok {
		return nil, os.ErrNotExist
	}
	return nil, nil // errors.Wrap(syscall.EPERM, "stat: ZIP filesystem is in write mode")
}

// Name returns the name of this file system.
func (fs *FS) Name() string {
	return "FS"
}

// Chmod changes the mode of the named file to mode.
func (fs *FS) Chmod(name string, mode os.FileMode) error {
	return errors.New("Chmod not implemented")
}

// Chtimes changes the access and modification times of the named file.
func (fs *FS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return errors.New("Chtimes not implemented")
}

// Close closes the file freeing the resource. Usually additional IO operations
// fail after closing.
func (fs *FS) Close() error {
	return fs.zipwriter.Close()
}

// Item describes files and directories in the XXX file system.
type Item struct {
	name string
	io.Writer
}

// Name returns the name of the file.
func (i Item) Name() string {
	return i.name
}

// Read fails in a write-only fs.
func (i Item) Read(b []byte) (n int, err error) {
	return 0, syscall.EPERM
}

// ReadAt fails in a write-only fs.
func (i Item) ReadAt(b []byte, off int64) (n int, err error) {
	return 0, syscall.EPERM
}

// Seek fails in a write-only fs.
func (i Item) Seek(offset int64, whence int) (ret int64, err error) {
	return 0, syscall.EPERM
}

// Stat fails in a write-only fs.
func (i Item) Stat() (os.FileInfo, error) {
	var fh zip.FileHeader
	return fh.FileInfo(), syscall.EPERM
}

// Sync fails in a write-only fs.
func (i Item) Sync() error {
	return syscall.EPERM
}

// Truncate fails in a write-only fs.
func (i Item) Truncate(size int64) error {
	return syscall.EPERM
}

// Close does not do anything.
func (i Item) Close() error {
	return nil
}

// WriteAt is not implemented.
func (i Item) WriteAt(b []byte, off int64) (n int, err error) {
	return 0, syscall.EPERM
}

// WriteString is not implemented.
func (i Item) WriteString(s string) (n int, err error) {
	return 0, syscall.EPERM
}

// Readdir fails in a write-only fs.
func (i Item) Readdir(count int) ([]os.FileInfo, error) {
	return []os.FileInfo{}, syscall.EPERM
}

// Readdirnames fails in a write-only fs.
func (i Item) Readdirnames(n int) ([]string, error) {
	return []string{}, syscall.EPERM
}

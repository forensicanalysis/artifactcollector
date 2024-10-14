// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-BSD file.

/*
Package zip provides support for reading and writing ZIP archives.

See: http://www.pkware.com/documents/casestudies/APPNOTE.TXT

This package does not support disk spanning.

A note about ZIP64:

To be backwards compatible the FileHeader has both 32 and 64 bit Size
fields. The 64 bit fields will always contain the correct value and
for normal archives both fields will be the same. For files requiring
the ZIP64 format the 32 bit fields will be 0xffffffff and the 64 bit
fields must be used instead.
*/
package aczip

const Deflate uint16 = 8

const (
	fileHeaderSignature      = 0x04034b50
	directoryHeaderSignature = 0x02014b50
	directoryEndSignature    = 0x06054b50
	directory64LocSignature  = 0x07064b50
	directory64EndSignature  = 0x06064b50
	dataDescriptorSignature  = 0x08074b50 // de-facto standard; required by OS X Finder
	fileHeaderLen            = 30         // + filename + extra
	directoryHeaderLen       = 46         // + filename + extra + comment
	directoryEndLen          = 22         // + comment
	dataDescriptorLen        = 16         // four uint32: descriptor signature, crc32, compressed size, size
	dataDescriptor64Len      = 24         // descriptor with 8 byte sizes
	directory64LocLen        = 20         //
	directory64EndLen        = 56         // + extra

	// version numbers
	zipVersion20 = 20 // 2.0
	zipVersion45 = 45 // 4.5 (reads and writes zip64 archives)

	// limits for non zip64 files
	uint16max = (1 << 16) - 1
	uint32max = (1 << 32) - 1

	// extra header id's
	zip64ExtraID = 0x0001 // zip64 Extended Information Extra Field
)

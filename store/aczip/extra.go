package aczip

import (
	"archive/zip"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
)

func isZip64(h *zip.FileHeader) bool {
	return h.CompressedSize64 >= uint32max || h.UncompressedSize64 >= uint32max
}

func (w *Writer) Exists(path string) (bool, error) {
	if w.closed {
		return false, errors.New("zip: exists from closed archive")
	}

	if w.last != nil && !w.last.closed {
		if err := w.last.close(); err != nil {
			return false, err
		}
	}

	for _, h := range w.dir {
		if h.Name == path {
			return true, nil
		}
	}

	return false, nil
}

func (w *Writer) Read(name string) ([]byte, error) {
	if w.closed {
		return nil, errors.New("zip: read from closed archive")
	}

	if w.last != nil && !w.last.closed {
		if err := w.last.close(); err != nil {
			return nil, err
		}
	}

	for _, h := range w.dir {
		if h.Name == name {
			return w.readFile(h)
		}
	}

	return nil, errors.New("zip: file not found")
}

func (w *Writer) readFile(h *header) ([]byte, error) {
	offset := w.cw.count

	bodyOffset, err := w.findBodyOffset(h)
	if err != nil {
		return nil, err
	}

	if _, err := w.cw.w.Seek(bodyOffset+int64(h.offset), 0); err != nil {
		return nil, err
	}

	// Create a limited reader to read only the compressed data
	limitedReader := io.LimitReader(w.cw.w, int64(h.CompressedSize64))

	// Create a flate reader to uncompress the data directly from the limited reader
	flateReader := flate.NewReader(limitedReader)
	defer flateReader.Close()

	b, err := ioutil.ReadAll(flateReader)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if _, err := w.cw.w.Seek(offset, 0); err != nil {
		return nil, err
	}

	return b, nil
}

func (w *Writer) findBodyOffset(h *header) (int64, error) {
	var buf [fileHeaderLen]byte
	if _, err := w.cw.w.ReadAt(buf[:], int64(h.offset)); err != nil {
		return 0, err
	}

	b := readBuf(buf[:])
	if sig := b.uint32(); sig != fileHeaderSignature {
		return 0, zip.ErrFormat
	}

	b = b[22:] // skip over most of the header
	filenameLen := int(b.uint16())
	extraLen := int(b.uint16())

	return int64(fileHeaderLen + filenameLen + extraLen), nil
}

type readBuf []byte

func (b *readBuf) uint8() uint8 {
	v := (*b)[0]
	*b = (*b)[1:]

	return v
}

func (b *readBuf) uint16() uint16 {
	v := binary.LittleEndian.Uint16(*b)
	*b = (*b)[2:]

	return v
}

func (b *readBuf) uint32() uint32 {
	v := binary.LittleEndian.Uint32(*b)
	*b = (*b)[4:]

	return v
}

func (b *readBuf) uint64() uint64 {
	v := binary.LittleEndian.Uint64(*b)
	*b = (*b)[8:]

	return v
}

func (b *readBuf) sub(n int) readBuf {
	b2 := (*b)[:n]
	*b = (*b)[n:]

	return b2
}

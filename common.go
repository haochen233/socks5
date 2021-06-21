package socks5

import (
	"errors"
	"io"
)

var errUnexpectMinusLength = errors.New("arg number should not be minus")

// ReadNBytes wrap io.ReadFull. read n bytes.
// The error is EOF only if no bytes were read.
// If an EOF happens after reading some but not all the bytes,
// ReadFull returns ErrUnexpectedEOF.
func ReadNBytes(reader io.Reader, n int) ([]byte, error) {
	if n < 0 {
		return nil, errUnexpectMinusLength
	}
	data := make([]byte, n)
	_, err := io.ReadFull(reader, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

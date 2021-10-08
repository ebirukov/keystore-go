package digest

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"
)

var (
	ErrNonCompleteRead = errors.New("read was not completed")
)

// Reader wrapper over the Reader that verifies the signature hash.
// Signature bytes are available in the trailing bytes of the read stream.
// The number of bytes is determined by the signature algorithm hash.Hash.
type Reader struct {
	r        *bufio.Reader
	md       hash.Hash
	signHash []byte
}

// NewReader create a Reader over the io.Reader,
// verifying signature corresponding to the algorithm hash.Hash.
func NewReader(r io.Reader, md hash.Hash) *Reader {
	return &Reader{r: bufio.NewReader(r), md: md}
}

// Read performs additional processing,
// calculating the signature upon reaching the end (io.EOF) of the read bytes.
func (d *Reader) Read(b []byte) (n int, err error) {
	if n, err = d.r.Read(b); err != nil {
		return
	}

	d.signHash, n, err = d.extractDigest(b[:n])
	if _, err := d.md.Write(b[:n]); err != nil {
		return n, fmt.Errorf("digest reader read error: %w", err)
	}

	return
}

// extractDigest extract digest from read bytes and rest of stream.
func (d *Reader) extractDigest(b []byte) (digest []byte, n int, err error) {
	n = len(b)
	if digest, err = d.r.Peek(d.md.Size()); errors.Is(err, io.EOF) {
		if d.md.Size() > (n + len(digest)) {
			return nil, len(b), fmt.Errorf("extract digest length less than %d : %w ", d.md.Size(), err)
		}

		n = n + len(digest) - d.md.Size() // calculate reading number of bytes before bytes of digest
		digest = append(b[n:], digest...) // collect bytes of digest
	}

	return
}

// VerifySign verifies the validity of the signature
// return false if the signature does not match the read data
// Causes ErrNonCompleteRead if not reached the end (io.EOF) of the read bytes.
func (d *Reader) VerifySign() (ok bool, err error) {
	if d.signHash == nil {
		err = ErrNonCompleteRead
	}

	ok = bytes.Equal(d.md.Sum(nil), d.signHash)

	return
}

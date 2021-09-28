package sign

import (
	"bufio"
	"bytes"
	"errors"
	"hash"
	"io"
)

var (
	NonCompleteRead = errors.New("read was not completed")
)

// Reader wrapper over the reader that verifies the signature hash.
// Signature bytes are available in the trailing bytes of the read stream.
// The number of bytes is determined by the signature algorithm hash.Hash
type reader struct {
	r        *bufio.Reader
	md       hash.Hash
	signHash []byte
}

// NewReader create a Reader over the io.Reader,
// verifying signature corresponding to the algorithm hash.Hash
func NewReader(r io.Reader, md hash.Hash) *reader {
	return &reader{r: bufio.NewReader(r), md: md}
}

// Read performs additional processing,
// calculating the signature upon reaching the end (io.EOF) of the read bytes
func (d *reader) Read(b []byte) (n int, err error) {
	n, err = d.r.Read(b)
	rest, eof := d.r.Peek(d.md.Size())
	if n+len(rest) < d.md.Size() {
		return
	}
	if eof != nil {
		err = eof
		nRead := n
		n = n + len(rest) - d.md.Size()
		d.md.Write(b[:n])
		d.signHash = append(b[n:nRead], rest...)
		b = b[:n]
	}
	if err == nil {
		d.md.Write(b[:n])
	}
	return
}

// verifySign verifies the validity of the signature
// return false if the signature does not match the read data
// Causes NonCompleteRead if not reached the end (io.EOF) of the read bytes
func (d *reader) verifySign() (ok bool, err error) {
	if d.signHash == nil {
		err = NonCompleteRead
	}
	hashSum := d.md.Sum(nil)
	ok = bytes.Compare(hashSum, d.signHash) == 0
	return
}

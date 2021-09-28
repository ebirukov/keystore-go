package keystore

import (
	"bufio"
	"bytes"
	"hash"
	"io"
)

// DigestVerifier wrapper over the reader that verifies the signature hash.
// Signature bytes are available in the trailing bytes of the read stream.
// The number of bytes is determined by the signature algorithm hash.Hash
type DigestVerifier struct {
	r  *bufio.Reader
	md hash.Hash
}

// NewDigestVerifier create a DigestVerifier over the io.Reader,
// verifying signature corresponding to the algorithm hash.Hash
func NewDigestVerifier(r io.Reader, md hash.Hash) *DigestVerifier {
	return &DigestVerifier{r: bufio.NewReader(r), md: md}
}

// Read performs additional processing,
// calculating the signature upon reaching the end (io.EOF) of the read bytes
func (d *DigestVerifier) Read(b []byte) (n int, err error) {
	n, err = d.r.Read(b)
	rest, eof := d.r.Peek(d.md.Size())
	if eof != nil {
		err = eof
		nRead := n
		n = n + len(rest) - d.md.Size()
		d.md.Write(b[:n])
		sign := append(b[n:nRead], rest...)
		d.verifySign(sign)
		b = b[:n]
	}
	if err == nil {
		d.md.Write(b[:n])
	}
	return
}

// verifySign verifies the validity of the signature
// Causes panic if the signature does not match the read data
func (d *DigestVerifier) verifySign(sign []byte) {
	hashSum := d.md.Sum(nil)
	if bytes.Compare(hashSum, sign) != 0 {
		panic("invalid data significant")
	}
}

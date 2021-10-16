package jserial

type Decoder interface {
	Decode(structure interface{}) error
}

// EncryptedSecurityKey describes encryption detail of security key.
type EncryptedSecurityKey struct {
	EncodedParams    []byte
	EncryptedContent []byte
	ParamsAlg        string
	SealAlg          string
}

type KeyRep struct {
	Type      string
	Algorithm string
	Format    string
	Encoded   []byte
}

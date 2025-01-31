package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/pavel-v-chernykh/keystore-go/v4/jserial"
)

var (
	ErrEntryNotFound           = errors.New("entry not found")
	ErrWrongEntryType          = errors.New("wrong entry type")
	ErrEmptyPrivateKey         = errors.New("empty private key")
	ErrEmptyCertificateType    = errors.New("empty certificate type")
	ErrEmptyCertificateContent = errors.New("empty certificate content")
	ErrShortPassword           = errors.New("short password")
)

const minPasswordLen = 6
const (
	JDKStoreType   = 0
	JCEKSStoreType = 1
)

// KeyStore is a mapping of alias to pointer to PrivateKeyEntry or TrustedCertificateEntry.
type KeyStore struct {
	m map[string]interface{}

	ordered   bool
	caseExact bool
	storeType int
}

// PrivateKeyEntry is an entry for private keys and associated certificates.
type PrivateKeyEntry struct {
	encryptedPrivateKey []byte

	CreationTime     time.Time
	PrivateKey       []byte
	CertificateChain []Certificate
}

// TrustedCertificateEntry is an entry for certificates only.
type TrustedCertificateEntry struct {
	CreationTime time.Time
	Certificate  Certificate
}

// Certificate describes type of certificate.
type Certificate struct {
	Type    string
	Content []byte
}

// SecurityKeyEntry is entry for JCEKS security key.
type SecurityKeyEntry struct {
	CreationTime         time.Time
	SecurityKey          []byte
	EncryptedSecurityKey jserial.EncryptedSecurityKey
}

type Option func(store *KeyStore)

// WithOrderedAliases sets ordered option to true. Orders aliases alphabetically.
func WithOrderedAliases() Option { return func(ks *KeyStore) { ks.ordered = true } }

// WithCaseExactAliases sets caseExact option to true. Preserves original case of aliases.
func WithCaseExactAliases() Option { return func(ks *KeyStore) { ks.caseExact = true } }

// WithStoreType sets storeType option value. The default keystore type is "jks" (storeType value is 0),
// which is a proprietary format. Other keystore formats are available: "jceks" (storeType value is 0).
func WithStoreType(storeType int) Option { return func(ks *KeyStore) { ks.storeType = storeType } }

// New returns new initialized instance of the KeyStore.
func New(options ...Option) KeyStore {
	ks := KeyStore{m: make(map[string]interface{})}

	for _, option := range options {
		option(&ks)
	}

	return ks
}

// Store signs keystore using password and writes its representation into w
// It is strongly recommended to fill password slice with zero after usage.
func (ks KeyStore) Store(w io.Writer, password []byte) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters: %w", minPasswordLen, ErrShortPassword)
	}

	kse := keyStoreEncoder{
		w:  w,
		md: sha1.New(),
	}

	passwordBytes := passwordBytes(password)
	defer zeroing(passwordBytes)

	if _, err := kse.md.Write(passwordBytes); err != nil {
		return fmt.Errorf("update digest with password: %w", err)
	}

	if _, err := kse.md.Write(whitenerMessage); err != nil {
		return fmt.Errorf("update digest with whitener message: %w", err)
	}

	var magic uint32

	switch ks.storeType {
	case JDKStoreType:
		magic = jksmagic
	case JCEKSStoreType:
		magic = jceksmagic
	}

	if err := kse.writeUint32(magic); err != nil {
		return fmt.Errorf("write jksmagic: %w", err)
	}
	// always write latest version
	if err := kse.writeUint32(version02); err != nil {
		return fmt.Errorf("write version: %w", err)
	}

	if err := kse.writeUint32(uint32(len(ks.m))); err != nil {
		return fmt.Errorf("write number of entries: %w", err)
	}

	for _, alias := range ks.Aliases() {
		switch typedEntry := ks.m[alias].(type) {
		case PrivateKeyEntry:
			if err := kse.writePrivateKeyEntry(alias, typedEntry); err != nil {
				return fmt.Errorf("write private key entry: %w", err)
			}
		case TrustedCertificateEntry:
			if err := kse.writeTrustedCertificateEntry(alias, typedEntry); err != nil {
				return fmt.Errorf("write trusted certificate entry: %w", err)
			}
		default:
			return errors.New("got invalid entry")
		}
	}

	if err := kse.writeBytes(kse.md.Sum(nil)); err != nil {
		return fmt.Errorf("write digest: %w", err)
	}

	return nil
}

// Load reads keystore representation from r and checks its signature.
// It is strongly recommended to fill password slice with zero after usage.
func (ks *KeyStore) Load(r io.Reader, password []byte) error {
	md := sha1.New()

	passwordBytes := passwordBytes(password)
	defer zeroing(passwordBytes)

	if _, err := md.Write(passwordBytes); err != nil {
		return fmt.Errorf("update digest with password: %w", err)
	}

	if _, err := md.Write(whitenerMessage); err != nil {
		return fmt.Errorf("update digest with whitener message: %w", err)
	}

	signReader := NewReader(r, md)
	ksd := newKeyStoreDecoder(signReader, md)

	readMagic, err := ksd.readUint32()
	if err != nil {
		return fmt.Errorf("read keystore type jks or jceks magic: %w", err)
	}

	switch readMagic {
	case jceksmagic:
		ks.storeType = JCEKSStoreType
	case jksmagic:
		ks.storeType = JDKStoreType
	default:
		return fmt.Errorf("invalid magic: %w", err)
	}

	version, err := ksd.readUint32()
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}

	entryNum, err := ksd.readUint32()
	if err != nil {
		return fmt.Errorf("read number of entries: %w", err)
	}

	for i := uint32(0); i < entryNum; i++ {
		alias, entry, err := ksd.readEntry(version)
		if err != nil {
			return fmt.Errorf("read %d entry: %w", i, err)
		}

		ks.m[alias] = entry
	}

	verified, err := signReader.VerifySign()
	if err != nil {
		return fmt.Errorf("read digest: %w", err)
	}

	if !verified {
		return errors.New("got invalid digest")
	}

	return nil
}

// SetPrivateKeyEntry adds PrivateKeyEntry into keystore by alias encrypted with password.
// It is strongly recommended to fill password slice with zero after usage.
func (ks KeyStore) SetPrivateKeyEntry(alias string, entry PrivateKeyEntry, password []byte) error {
	if err := entry.validate(); err != nil {
		return fmt.Errorf("validate private key entry: %w", err)
	}

	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters: %w", minPasswordLen, ErrShortPassword)
	}

	var (
		epk []byte
		err error
	)

	switch ks.storeType {
	case JDKStoreType:
		epk, err = encrypt(rand.Reader, entry.PrivateKey, password)
	case JCEKSStoreType:
		epk, err = encryptJCEKSKey(rand.Reader, entry.PrivateKey, password)
	default:
		err = errors.New("unsupported type of keystore")
	}

	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	entry.encryptedPrivateKey = epk

	ks.m[ks.convertAlias(alias)] = entry

	return nil
}

// GetPrivateKeyEntry returns PrivateKeyEntry from the keystore by the alias decrypted with the password.
// It is strongly recommended to fill password slice with zero after usage.
func (ks KeyStore) GetPrivateKeyEntry(alias string, password []byte) (PrivateKeyEntry, error) {
	e, ok := ks.m[ks.convertAlias(alias)]
	if !ok {
		return PrivateKeyEntry{}, ErrEntryNotFound
	}

	pke, ok := e.(PrivateKeyEntry)
	if !ok {
		return PrivateKeyEntry{}, ErrWrongEntryType
	}

	dpk, err := decrypt(pke.encryptedPrivateKey, password)
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("decrypte private key: %w", err)
	}

	pke.encryptedPrivateKey = nil
	pke.PrivateKey = dpk

	return pke, nil
}

// IsPrivateKeyEntry returns true if the keystore has PrivateKeyEntry by the alias.
func (ks KeyStore) IsPrivateKeyEntry(alias string) bool {
	_, ok := ks.m[ks.convertAlias(alias)].(PrivateKeyEntry)

	return ok
}

// SetTrustedCertificateEntry adds TrustedCertificateEntry into keystore by alias.
func (ks KeyStore) SetTrustedCertificateEntry(alias string, entry TrustedCertificateEntry) error {
	if err := entry.validate(); err != nil {
		return fmt.Errorf("validate trusted certificate entry: %w", err)
	}

	ks.m[ks.convertAlias(alias)] = entry

	return nil
}

// GetTrustedCertificateEntry returns TrustedCertificateEntry from the keystore by the alias.
func (ks KeyStore) GetTrustedCertificateEntry(alias string) (TrustedCertificateEntry, error) {
	e, ok := ks.m[ks.convertAlias(alias)]
	if !ok {
		return TrustedCertificateEntry{}, ErrEntryNotFound
	}

	tce, ok := e.(TrustedCertificateEntry)
	if !ok {
		return TrustedCertificateEntry{}, ErrWrongEntryType
	}

	return tce, nil
}

// IsTrustedCertificateEntry returns true if the keystore has TrustedCertificateEntry by the alias.
func (ks KeyStore) IsTrustedCertificateEntry(alias string) bool {
	_, ok := ks.m[ks.convertAlias(alias)].(TrustedCertificateEntry)

	return ok
}

func (ks KeyStore) GetSecurityKeyEntry(alias string, password []byte) (SecurityKeyEntry, error) {
	e, ok := ks.m[ks.convertAlias(alias)]
	if !ok {
		return SecurityKeyEntry{}, ErrEntryNotFound
	}

	ske, ok := e.(SecurityKeyEntry)
	if !ok {
		return SecurityKeyEntry{}, ErrWrongEntryType
	}

	dsk, err := decryptSecurityKey(ske.EncryptedSecurityKey, password)
	if err != nil {
		return SecurityKeyEntry{}, fmt.Errorf("decrypt security key: %w", err)
	}

	repKey := &jserial.KeyRep{}
	err = jserial.NewDecoder(bytes.NewReader(dsk)).Decode(repKey)

	if err != nil {
		return SecurityKeyEntry{}, fmt.Errorf("decrypt security key: %w", err)
	}

	ske.SecurityKey = repKey.Encoded
	ske.EncryptedSecurityKey = jserial.EncryptedSecurityKey{}

	return ske, nil
}

// DeleteEntry deletes entry from the keystore.
func (ks KeyStore) DeleteEntry(alias string) {
	delete(ks.m, ks.convertAlias(alias))
}

// Aliases returns slice of all aliases from the keystore.
// Aliases returns slice of all aliases sorted alphabetically if keystore created using WithOrderedAliases option.
func (ks KeyStore) Aliases() []string {
	as := make([]string, 0, len(ks.m))
	for a := range ks.m {
		as = append(as, a)
	}

	if ks.ordered {
		sort.Strings(as)
	}

	return as
}

func (ks KeyStore) convertAlias(alias string) string {
	if ks.caseExact {
		return alias
	}

	return strings.ToLower(alias)
}

func (e PrivateKeyEntry) validate() error {
	if len(e.PrivateKey) == 0 {
		return ErrEmptyPrivateKey
	}

	for i, c := range e.CertificateChain {
		if err := c.validate(); err != nil {
			return fmt.Errorf("validate certificate %d in chain: %w", i, err)
		}
	}

	return nil
}

func (e TrustedCertificateEntry) validate() error {
	return e.Certificate.validate()
}

func (c Certificate) validate() error {
	if len(c.Type) == 0 {
		return ErrEmptyCertificateType
	}

	if len(c.Content) == 0 {
		return ErrEmptyCertificateContent
	}

	return nil
}

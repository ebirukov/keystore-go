package keystore

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"github.com/pavel-v-chernykh/keystore-go/v4/jserial"
)

const saltLen = 20

var (
	jdkPrivateKeyAlgorithmOid = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1})
	jcePrivateKeyAlgorithmOid = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 42, 2, 19, 1})
)

type keyInfo struct {
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func decrypt(data []byte, password []byte) ([]byte, error) {
	var keyInfo keyInfo

	asn1Rest, err := asn1.Unmarshal(data, &keyInfo)
	if err != nil {
		return nil, fmt.Errorf("unmarshal encrypted key: %w", err)
	}

	if len(asn1Rest) > 0 {
		return nil, errors.New("got extra data in encrypted key")
	}

	switch {
	case keyInfo.Algo.Algorithm.Equal(jdkPrivateKeyAlgorithmOid):
		return decryptJDKKey(keyInfo, password)
	case keyInfo.Algo.Algorithm.Equal(jcePrivateKeyAlgorithmOid):
		dec, err := NewDecryptCipher(password, keyInfo.Algo.Parameters.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("decrypt security key: %w", err)
		}

		return dec.Decrypt(keyInfo.PrivateKey), nil
	default:
		return nil, errors.New("got unsupported private key encryption algorithm")
	}
}

func decryptJDKKey(keyInfo keyInfo, password []byte) ([]byte, error) {
	md := sha1.New()

	passwordBytes := passwordBytes(password)
	defer zeroing(passwordBytes)

	salt := make([]byte, saltLen)
	copy(salt, keyInfo.PrivateKey)
	encryptedKeyLen := len(keyInfo.PrivateKey) - saltLen - md.Size()
	numRounds := encryptedKeyLen / md.Size()

	if encryptedKeyLen%md.Size() != 0 {
		numRounds++
	}

	encryptedKey := make([]byte, encryptedKeyLen)
	copy(encryptedKey, keyInfo.PrivateKey[saltLen:])

	xorKey := make([]byte, encryptedKeyLen)

	digest := salt

	for i, xorOffset := 0, 0; i < numRounds; i++ {
		if _, err := md.Write(passwordBytes); err != nil {
			return nil, fmt.Errorf("update digest with password on %d round: %w", i, err)
		}

		if _, err := md.Write(digest); err != nil {
			return nil, fmt.Errorf("update digest with digest from previous round on %d round: %w", i, err)
		}

		digest = md.Sum(nil)
		md.Reset()
		copy(xorKey[xorOffset:], digest)
		xorOffset += md.Size()
	}

	plainKey := make([]byte, encryptedKeyLen)
	for i := 0; i < len(plainKey); i++ {
		plainKey[i] = encryptedKey[i] ^ xorKey[i]
	}

	if _, err := md.Write(passwordBytes); err != nil {
		return nil, fmt.Errorf("update digest with password: %w", err)
	}

	if _, err := md.Write(plainKey); err != nil {
		return nil, fmt.Errorf("update digest with plain key: %w", err)
	}

	digest = md.Sum(nil)
	md.Reset()

	digestOffset := saltLen + encryptedKeyLen
	if !bytes.Equal(digest, keyInfo.PrivateKey[digestOffset:digestOffset+len(digest)]) {
		return nil, errors.New("got invalid digest")
	}

	return plainKey, nil
}

func encryptJCEKSKey(rand io.Reader, plainKey []byte, password []byte) ([]byte, error) {
	parameters := generatePBEParams(rand, 5000)

	enc := NewEncryptCipher(password, parameters)

	encryptedKey := enc.Encrypt(plainKey)

	keyInfo := keyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: jcePrivateKeyAlgorithmOid,
			Parameters: asn1.RawValue{
				FullBytes: parameters.Encode(),
			},
		},
		PrivateKey: encryptedKey,
	}

	encodedKey, err := asn1.Marshal(keyInfo)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted key: %w", err)
	}

	return encodedKey, nil
}

func encrypt(rand io.Reader, plainKey []byte, password []byte) ([]byte, error) {
	md := sha1.New()

	passwordBytes := passwordBytes(password)
	defer zeroing(passwordBytes)

	plainKeyLen := len(plainKey)
	numRounds := plainKeyLen / md.Size()

	if plainKeyLen%md.Size() != 0 {
		numRounds++
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}

	xorKey := make([]byte, plainKeyLen)

	digest := salt

	for i, xorOffset := 0, 0; i < numRounds; i++ {
		if _, err := md.Write(passwordBytes); err != nil {
			return nil, fmt.Errorf("update digest with password on %d round: %w", i, err)
		}

		if _, err := md.Write(digest); err != nil {
			return nil, fmt.Errorf("update digest with digest from prevous round on %d round: %w", i, err)
		}

		digest = md.Sum(nil)
		md.Reset()
		copy(xorKey[xorOffset:], digest)
		xorOffset += md.Size()
	}

	tmpKey := make([]byte, plainKeyLen)
	for i := 0; i < plainKeyLen; i++ {
		tmpKey[i] = plainKey[i] ^ xorKey[i]
	}

	encryptedKey := make([]byte, saltLen+plainKeyLen+md.Size())
	encryptedKeyOffset := 0
	copy(encryptedKey[encryptedKeyOffset:], salt)
	encryptedKeyOffset += saltLen
	copy(encryptedKey[encryptedKeyOffset:], tmpKey)
	encryptedKeyOffset += plainKeyLen

	if _, err := md.Write(passwordBytes); err != nil {
		return nil, fmt.Errorf("update digest with password: %w", err)
	}

	if _, err := md.Write(plainKey); err != nil {
		return nil, fmt.Errorf("udpate digest with plain key: %w", err)
	}

	digest = md.Sum(nil)
	md.Reset()
	copy(encryptedKey[encryptedKeyOffset:], digest)

	keyInfo := keyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  jdkPrivateKeyAlgorithmOid,
			Parameters: asn1.RawValue{Tag: 5},
		},
		PrivateKey: encryptedKey,
	}

	encodedKey, err := asn1.Marshal(keyInfo)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted key: %w", err)
	}

	return encodedKey, nil
}

// decryptSecurityKey uses Java's custom/unpublished PBEWithMD5AndTripleDES algorithm.
func decryptSecurityKey(encrypted jserial.EncryptedSecurityKey, password []byte) ([]byte, error) {
	dec, err := NewDecryptCipher(password, encrypted.EncodedParams)
	if err != nil {
		return nil, fmt.Errorf("decrypt security key: %w", err)
	}

	return dec.Decrypt(encrypted.EncryptedContent), nil
}

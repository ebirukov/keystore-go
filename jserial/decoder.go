package jserial

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jkeys089/jserial"
)

func newKeyRep(objDef map[string]interface{}) KeyRep {
	k := KeyRep{}
	encoded := intToBytes(objDef["encoded"].([]interface{}))
	k.Encoded = encoded

	if alg, ok := objDef["algorithm"].(string); ok {
		k.Algorithm = alg
	}

	if format, ok := objDef["format"].(string); ok {
		k.Format = format
	}

	return k
}

func newSecurityKey(parseData map[string]interface{}) EncryptedSecurityKey {
	sk := EncryptedSecurityKey{}
	if encodedParams, ok := parseData["encodedParams"].([]interface{}); ok {
		sk.EncodedParams = intToBytes(encodedParams)
	}

	if encryptedContent, ok := parseData["encryptedContent"].([]interface{}); ok {
		sk.EncryptedContent = intToBytes(encryptedContent)
	}

	if pa, ok := parseData["paramsAlg"].(string); ok {
		sk.ParamsAlg = pa
	}

	if sa, ok := parseData["sealAlg"].(string); ok {
		sk.SealAlg = sa
	}

	return sk
}

func intToBytes(v []interface{}) (res []byte) {
	for i := 0; i < len(v); i++ {
		if b, ok := v[i].(int8); ok {
			res = append(res, byte(b))
		}
	}

	return
}

type decoder struct {
	parser *jserial.SerializedObjectParser
}

func NewDecoder(reader io.Reader) Decoder {
	return &decoder{
		parser: jserial.NewSerializedObjectParser(reader),
	}
}

func (s *decoder) Decode(object interface{}) (err error) {
	if object == nil {
		err = errors.New("deserialize: object is nil")

		return
	}

	var (
		content []interface{}
	)

	if content, err = s.parser.ParseSerializedObject(); content == nil || len(content) != 1 {
		return
	}

	parseData, ok := content[0].(map[string]interface{})

	if !ok {
		panic("deserialize: unknown type of content")
	}

	switch v := object.(type) {
	case *KeyRep:
		*v = newKeyRep(parseData)
	case *EncryptedSecurityKey:
		*v = newSecurityKey(parseData)
	default:
		err = fmt.Errorf(fmt.Sprintf("unknown jserial object %v", v))
	}

	if err != nil && strings.Contains(err.Error(), "unknown type") {
		err = nil
	}

	return err
}

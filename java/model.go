package java

type ObjectBuilder interface {
	Build(parseData map[string]interface{}) error
	Name() string
}

// EncryptedSecurityKey describes encryption detail of security key.
type EncryptedSecurityKey struct {
	EncodedParams    []byte
	EncryptedContent []byte
	ParamsAlg        string
	SealAlg          string
}

type KepRep struct {
	Type      string
	Algorithm string
	Format    string
	Encoded   []byte
}

func (k *KepRep) Name() string {
	return "java.security.KeyRep"
}

func (k *KepRep) Build(objDef map[string]interface{}) error {
	encoded := intToBytes(objDef["encoded"].([]interface{}))
	k.Encoded = encoded

	if alg, ok := objDef["algorithm"].(string); ok {
		k.Algorithm = alg
	}

	if format, ok := objDef["format"].(string); ok {
		k.Format = format
	}

	return nil
}

func (e *EncryptedSecurityKey) Name() string {
	return ""
}

func (e *EncryptedSecurityKey) Build(parseData map[string]interface{}) error {
	if encodedParams, ok := parseData["encodedParams"].([]interface{}); ok {
		e.EncodedParams = intToBytes(encodedParams)
	}

	if encryptedContent, ok := parseData["encryptedContent"].([]interface{}); ok {
		e.EncryptedContent = intToBytes(encryptedContent)
	}

	if pa, ok := parseData["paramsAlg"].(string); ok {
		e.ParamsAlg = pa
	}

	if sa, ok := parseData["sealAlg"].(string); ok {
		e.SealAlg = sa
	}

	return nil
}

func intToBytes(v []interface{}) (res []byte) {
	for i := 0; i < len(v); i++ {
		if b, ok := v[i].(int8); ok {
			res = append(res, byte(b))
		}
	}

	return
}

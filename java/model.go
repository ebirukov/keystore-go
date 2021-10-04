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
	k.Algorithm = objDef["algorithm"].(string)
	k.Format = objDef["format"].(string)
	return nil
}

func (e EncryptedSecurityKey) Name() string {
	return ""
}

func (e EncryptedSecurityKey) Build(parseData map[string]interface{}) error {
	encodedParams := intToBytes(parseData["encodedParams"].([]interface{}))
	encryptedContent := intToBytes(parseData["encryptedContent"].([]interface{}))
	e.EncodedParams = encodedParams
	e.EncryptedContent = encryptedContent
	e.ParamsAlg = parseData["paramsAlg"].(string)
	e.SealAlg = parseData["sealAlg"].(string)
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

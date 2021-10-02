package java

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

func NewKepRep(objDef map[string]interface{}) KepRep {
	encoded := intToBytes(objDef["encoded"].([]interface{}))
	return KepRep{
		//Type:        objDef["type"].(string),
		Algorithm: objDef["algorithm"].(string),
		Format:    objDef["format"].(string),
		Encoded:   encoded}
}

func NewEncryptedSecurityKey(objDef map[string]interface{}) EncryptedSecurityKey {
	encodedParams := intToBytes(objDef["encodedParams"].([]interface{}))
	encryptedContent := intToBytes(objDef["encryptedContent"].([]interface{}))
	return EncryptedSecurityKey{
		EncodedParams:    encodedParams,
		EncryptedContent: encryptedContent,
		ParamsAlg:        objDef["paramsAlg"].(string),
		SealAlg:          objDef["sealAlg"].(string),
	}
}

func intToBytes(v []interface{}) (res []byte) {
	for i := 0; i < len(v); i++ {
		if b, ok := v[i].(int8); ok {
			res = append(res, byte(b))
		}
	}
	return
}

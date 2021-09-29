package java

import "time"

type SecurityKeyEntry struct {
	CreationTime     time.Time
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

func NewSecurityKeyEntry(objDef map[string]interface{}) SecurityKeyEntry {
	encodedParams := intToBytes(objDef["encodedParams"].([]interface{}))
	encryptedContent := intToBytes(objDef["encryptedContent"].([]interface{}))
	return SecurityKeyEntry{
		//CreationTime: creationTime,
		EncodedParams:    encodedParams,
		EncryptedContent: encryptedContent,
		ParamsAlg:        objDef["paramsAlg"].(string),
		SealAlg:          objDef["sealAlg"].(string),
	}
}

func intToBytes(v []interface{}) (res []byte) {
	res = make([]byte, len(v))
	for i := 0; i < len(v); i++ {
		if b, ok := v[i].(int8); ok {
			res[i] = byte(b)
		}
	}
	return
}

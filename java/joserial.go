package java

import (
	"errors"
	"github.com/jkeys089/jserial"
	"io"
	"strings"
)

var (
	UnknownType = errors.New("unknown structure type")
)

type Serializable interface {
	Serialize(structure interface{}) error
	Deserialize(structure interface{}) (obj interface{}, err error)
}

type serializator struct {
	parser *jserial.SerializedObjectParser
}

func New(reader io.Reader) *serializator {
	return &serializator{
		parser: jserial.NewSerializedObjectParser(reader),
	}
}

func (s *serializator) Deserialize(structureType interface{}) (obj interface{}, err error) {
	var content []interface{}
	if content, err = s.parser.ParseSerializedObject(); content == nil || len(content) != 1 {
		return
	}
	if javaObject, ok := content[0].(map[string]interface{}); ok {
		switch structureType.(type) {
		case KepRep:
			obj = NewKepRep(javaObject)
		case EncryptedSecurityKey:
			obj = NewEncryptedSecurityKey(javaObject)
		default:
			err = UnknownType
		}
	}
	if err != nil && strings.Contains(err.Error(), "unknown type") {
		err = nil
	}
	return
}

func (s *serializator) Serialize(_ interface{}) error {
	return errors.New("serialization not implemented")
}

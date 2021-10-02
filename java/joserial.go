package java

import (
	"errors"
	"github.com/jkeys089/jserial" //nolint:goimports,gci
	"io"
	"strings"
)

var (
	ErrUnknownType = errors.New("unknown structure type")
)

type Serializable interface {
	Serialize(structure interface{}) error
	Deserialize(structure interface{}) (obj interface{}, err error)
}

type Serializator struct {
	parser *jserial.SerializedObjectParser
}

func New(reader io.Reader) *Serializator {
	return &Serializator{
		parser: jserial.NewSerializedObjectParser(reader),
	}
}

func (s *Serializator) Deserialize(structureType interface{}) (obj interface{}, err error) {
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
			err = ErrUnknownType
		}
	}
	if err != nil && strings.Contains(err.Error(), "unknown type") {
		err = nil
	}
	return
}

func (s *Serializator) Serialize(_ interface{}) error {
	return errors.New("serialization not implemented")
}

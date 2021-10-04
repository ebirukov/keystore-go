package java

import (
	"errors"
	"io"
	"strings"

	"github.com/jkeys089/jserial"
)

type Serializable interface {
	Serialize(w io.Writer, structure interface{}) error
	Deserialize(structure ObjectBuilder) error
}

type Serializator struct {
	parser *jserial.SerializedObjectParser
}

func New(reader io.Reader) *Serializator {
	return &Serializator{
		parser: jserial.NewSerializedObjectParser(reader),
	}
}

func (s *Serializator) Deserialize(object ObjectBuilder) (err error) {
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
	err = object.Build(parseData)
	if err != nil && strings.Contains(err.Error(), "unknown type") {
		err = nil
	}

	return
}

func (s *Serializator) Serialize(w io.Writer, structure interface{}) error {
	return errors.New("serialization not implemented")
}

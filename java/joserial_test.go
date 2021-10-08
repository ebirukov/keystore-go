package java

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/jkeys089/jserial"
)

var (
	javaKeyRepHex = "aced0005737200146a6176612e73656375726974792e4b6579526570bdf94fb3889aa5430200044c0009616c676f726974686d7400124c6a6176612f6c616e672f537472696e673b5b0007656e636f6465647400025b424c0006666f726d617471007e00014c00047479706574001b4c6a6176612f73656375726974792f4b657952657024547970653b7870740010504245576974684d4435416e64444553757200025b42acf317f8060854e00200007870000000087665744c654f63317400035241577e7200196a6176612e73656375726974792e4b6579526570245479706500000000000000001200007872000e6a6176612e6c616e672e456e756d00000000000000001200007870740006534543524554" // nolint
)

func TestSerializator_Deserialize(t *testing.T) {
	t.Parallel()

	var decode = func(hexStr string) []byte {
		data, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Error(err)
		}

		return data
	}

	type fields struct {
		parser *jserial.SerializedObjectParser
	}

	type args struct {
		buildType ObjectBuilder
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    ObjectBuilder
		wantErr bool
	}{
		{
			"deserializeNil",
			fields{jserial.NewSerializedObjectParser(bytes.NewReader(nil))},
			args{&KepRep{}},
			&KepRep{},
			true,
		},
		{
			"deserializeKepRep",
			fields{jserial.NewSerializedObjectParser(bytes.NewReader(decode(javaKeyRepHex)))},
			args{&KepRep{}},
			&KepRep{
				Algorithm: "PBEWithMD5AndDES",
				Format:    "RAW",
				Encoded:   []byte("vetLeOc1"),
			},
			false,
		},
		{
			"deserializeNilType",
			fields{jserial.NewSerializedObjectParser(bytes.NewReader(decode(javaKeyRepHex)))},
			args{nil},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Serializator{
				parser: tt.fields.parser,
			}
			err := s.Deserialize(tt.args.buildType)

			got := tt.args.buildType
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Deserialize() got = %+v, want=%+v", got, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Deserialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

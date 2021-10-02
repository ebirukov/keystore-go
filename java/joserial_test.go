package java

import (
	"bytes"
	"encoding/hex"
	"github.com/jkeys089/jserial"
	"reflect"
	"testing"
)

type Unknown struct{}

var (
	javaKeyRepHex = "aced0005737200146a6176612e73656375726974792e4b6579526570bdf94fb3889aa5430200044c0009616c676f726974686d7400124c6a6176612f6c616e672f537472696e673b5b0007656e636f6465647400025b424c0006666f726d617471007e00014c00047479706574001b4c6a6176612f73656375726974792f4b657952657024547970653b7870740010504245576974684d4435416e64444553757200025b42acf317f8060854e00200007870000000087665744c654f63317400035241577e7200196a6176612e73656375726974792e4b6579526570245479706500000000000000001200007872000e6a6176612e6c616e672e456e756d00000000000000001200007870740006534543524554" // nolint
)

func Test_serializator_Deserialize(t *testing.T) {
	t.Parallel()
	decode := func(hexStr string) []byte {
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
		structureType interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantObj interface{}
		wantErr bool
	}{
		{
			"deserializeNil",
			fields{jserial.NewSerializedObjectParser(bytes.NewReader(nil))},
			args{KepRep{}},
			nil,
			true,
		},
		{
			"deserializeKepRep",
			fields{jserial.NewSerializedObjectParser(bytes.NewReader(decode(javaKeyRepHex)))},
			args{KepRep{}},
			KepRep{
				Algorithm: "PBEWithMD5AndDES",
				Format:    "RAW",
				Encoded:   []byte("vetLeOc1"),
			},
			false,
		},
		{
			"deserializeUnknownType",
			fields{jserial.NewSerializedObjectParser(bytes.NewReader(decode(javaKeyRepHex)))},
			args{Unknown{}},
			nil,
			true,
		},
	}
	for _, tt := range tests { //nolint
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &serializator{
				parser: tt.fields.parser,
			}
			gotObj, err := s.Deserialize(tt.args.structureType)
			if (err != nil) != tt.wantErr {
				t.Errorf("Deserialize() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(gotObj, tt.wantObj) {
				t.Errorf("Deserialize() gotObj = %v, want %v", gotObj, tt.wantObj)
			}
		})
	}
}

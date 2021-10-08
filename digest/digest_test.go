package digest

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"io"
	"reflect"
	"testing"
)

func TestReader_Read(t *testing.T) {
	t.Parallel()

	type fields struct {
		r  *bufio.Reader
		md hash.Hash
	}

	type args struct {
		b []byte
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantN   int
		wantErr bool
	}{
		{
			"emptyReader",
			fields{
				r:  bufio.NewReader(bytes.NewReader(nil)),
				md: sha1.New(),
			},
			args{make([]byte, 1)},
			0,
			true,
		},
		{
			"unsignSmallReader",
			fields{
				r:  bufio.NewReader(bytes.NewReader(make([]byte, 10))),
				md: sha1.New(),
			},
			args{make([]byte, 4)},
			4,
			true,
		},
		{
			"oneByteSigSizeReaderEOF",
			fields{
				r:  bufio.NewReader(bytes.NewReader(make([]byte, 21))),
				md: sha1.New(),
			},
			args{make([]byte, 22)},
			1,
			true,
		},
	}
	for _, tt := range tests {
		d := &Reader{
			r:  tt.fields.r,
			md: tt.fields.md,
		}
		gotN, err := d.Read(tt.args.b)

		if (err != nil) != tt.wantErr {
			t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)

			return
		}

		if gotN != tt.wantN {
			t.Errorf("Read() gotN = %v, want %v", gotN, tt.wantN)
		}
	}
}

func TestReaderVerifier(t *testing.T) {
	t.Parallel()

	expected, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")

	if err != nil {
		t.Error(err)
	}

	md := sha1.New()
	if _, err = md.Write(expected); err != nil {
		t.Error(err)
	}

	data := append(expected, md.Sum(nil)...)
	md.Reset()
	digestReader := NewReader(bytes.NewReader(data), md)

	actualData, err := io.ReadAll(digestReader)
	if err != nil {
		t.Error(err)
	}

	ok, err := digestReader.VerifySign()
	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.Failed()
	}

	if !reflect.DeepEqual(actualData, expected) {
		t.Errorf("invalid stream data actualData='%v' expected='%v'", actualData, expected)
	}
}

func TestReader_verifySign(t *testing.T) {
	t.Parallel()

	type fields struct {
		r            *bufio.Reader
		md           hash.Hash
		signHash     []byte
		completeRead bool
	}

	decode := func(hexStr string) []byte {
		data, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Error(err)
		}

		return data
	}
	prepareReader := func(hexData string, hexSign string) (r *bufio.Reader) {
		data := append(decode(hexData), decode(hexSign)...)
		r = bufio.NewReader(bytes.NewReader(data))

		return
	}

	tests := []struct {
		name    string
		fields  fields
		wantOk  bool
		wantErr bool
	}{
		{
			"validSig",
			fields{
				r: prepareReader(
					"0102030405060708090a0b0c0d0e0f10",
					"2cc429832452134629f1f6d296ec8aefb4e4d8a9"),
				md:           sha1.New(),
				signHash:     decode("2cc429832452134629f1f6d296ec8aefb4e4d8a9"),
				completeRead: true,
			},
			true,
			false,
		},
		{
			"readerNonComplete",
			fields{
				r: prepareReader(
					"7465737464617461",
					"44115646e09ab3481adc2b1dc17be10dd9cdaa09"),
				md:           sha1.New(),
				signHash:     decode("44115646e09ab3481adc2b1dc17be10dd9cdaa09"),
				completeRead: false,
			},
			false,
			false,
		},
		{
			"readerNonCompleteError",
			fields{
				r: prepareReader(
					"7465737464617461",
					"44115646e09ab3481adc2b1dc17be10dd9cdaa09"),
				md:           sha1.New(),
				signHash:     nil,
				completeRead: false,
			},
			false,
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fields := tt.fields
			d := &Reader{
				r:        fields.r,
				md:       fields.md,
				signHash: fields.signHash,
			}

			if fields.completeRead {
				if _, err := io.ReadAll(d); err != nil {
					t.Error(err)
				}
			}

			gotOk, err := d.VerifySign()
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySign() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if gotOk != tt.wantOk {
				t.Errorf("VerifySign() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

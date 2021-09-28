package keystore

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

func TestDigestVerifier(t *testing.T) {
	md := sha1.New()
	expected, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Error(err)
	}
	md.Write(expected)
	data := append(expected, md.Sum(nil)...)
	md.Reset()
	digestReader := NewDigestVerifier(bytes.NewReader(data), md)
	actualData, err := io.ReadAll(digestReader)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(actualData, expected) {
		t.Errorf("invalid stream data actualData='%v' expected='%v'", actualData, expected)
	}
}

func TestDigestVerifier_Read(t *testing.T) {
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
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DigestVerifier{
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
		})
	}
}

func TestNewDigestVerifier(t *testing.T) {
	type args struct {
		r  io.Reader
		md hash.Hash
	}
	tests := []struct {
		name string
		args args
		want *DigestVerifier
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewDigestVerifier(tt.args.r, tt.args.md); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDigestVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

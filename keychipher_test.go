package keystore

import (
	"fmt"
	"reflect"
	"testing"
)

func TestCipher_Encrypt(t *testing.T) {
	password := []byte("my_password")
	params := pbeParams{
		Salt:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2000,
	}
	fmt.Printf("%v", params.Encode())
	cipher := NewEncryptCipher(password, params)

	type args struct {
		src []byte
	}

	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			"case",
			args{
				src: []byte("my_secret"),
			},
			[]byte{0x91, 0x10, 0x29, 0xf1, 0x2b, 0x07, 0x73, 0x9f, 0x98, 0x0a, 0x25, 0x70, 0x5f, 0x00, 0xb9, 0xc7},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := cipher.Encrypt(tt.args.src); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Encrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewDecryptCipher(t *testing.T) {
	type args struct {
		password      []byte
		encodedParams []byte
	}

	tests := []struct {
		name    string
		args    args
		want    *Cipher
		wantErr bool
	}{
		{
			"case1",
			args{
				password:      []byte("password"),
				encodedParams: []byte{48, 14, 4, 8, 1, 2, 3, 4, 5, 6, 7, 8, 2, 2, 7, 208},
			},
			&Cipher{},
			false,
		},
		{
			"case2",
			args{
				password:      []byte("password"),
				encodedParams: []byte{48, 14, 4, 8, 1, 2, 3, 4, 5, 6, 7},
			},
			nil,
			true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDecryptCipher(tt.args.password, tt.args.encodedParams)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDecryptCipher() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got == nil && got != tt.want {
				t.Errorf("NewDecryptCipher() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPBEParams(t *testing.T) {
	type args struct {
		encodedParams []byte
	}

	tests := []struct {
		name    string
		args    args
		want    *pbeParams
		wantErr bool
	}{
		{
			"validPBE",
			args{
				encodedParams: []byte{48, 14, 4, 8, 1, 2, 3, 4, 5, 6, 7, 8, 2, 2, 7, 208},
			},
			&pbeParams{
				Salt:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
				Iterations: 2000,
			},
			false,
		},
		{
			"invalidPBE",
			args{
				encodedParams: []byte{48, 14, 4, 8, 1, 2, 3, 4, 5, 6},
			},
			nil,
			true,
		},
		{
			"nilPBE",
			args{
				encodedParams: nil,
			},
			nil,
			true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeParams(tt.args.encodedParams)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodePBEParams() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodePBEParams() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getDerivedKey(t *testing.T) {
	type args struct {
		password []byte
		salt     []byte
		count    int
	}

	tests := []struct {
		name  string
		args  args
		want  []byte
		want1 []byte
	}{
		{
			"case1",
			args{
				password: []byte{'m', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'},
				salt:     []byte{0x69, 0xea, 0xff, 0x28, 0x65, 0x85, 0x0a, 0x68},
				count:    2000,
			},
			[]byte{0x8c, 0xe5, 0x38, 0xd7, 0x99, 0xf2, 0x39, 0xe7,
				0x70, 0x03, 0x4b, 0xe6, 0xbf, 0xd3, 0x81, 0x94,
				0x2f, 0xa3, 0xee, 0xcd, 0x18, 0xbf, 0xa7, 0xcb},
			[]byte{0x36, 0x91, 0x08, 0x2b, 0xf4, 0x99, 0x2e, 0x92},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := getDerivedKey(tt.args.password, tt.args.salt, tt.args.count)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getDerivedKey() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("getDerivedKey() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestCipher_Decrypt(t *testing.T) {
	password := []byte("my_password")
	params := pbeParams{
		Salt:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2000,
	}
	cipher, err := NewDecryptCipher(password, params.Encode())

	if err != nil {
		t.Error(err)
	}

	type fields struct {
		cipher *Cipher
	}

	type args struct {
		src []byte
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   []byte
	}{
		{
			"case1",
			fields{cipher: cipher},
			args{
				src: []byte{0x91, 0x10, 0x29, 0xf1, 0x2b, 0x07, 0x73, 0x9f, 0x98, 0x0a, 0x25, 0x70, 0x5f, 0x00, 0xb9, 0xc7},
			},
			[]byte("my_secret"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fields.cipher
			if got := c.Decrypt(tt.args.src); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

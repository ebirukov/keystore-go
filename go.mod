module github.com/pavel-v-chernykh/keystore-go/v4

go 1.14

require (
	github.com/ebirukov/PBEWithMD5AndTripleDES v0.0.0-20210929151205-e49bf95fc13a
	github.com/jkeys089/jserial v1.0.0
)

replace github.com/jkeys089/jserial => ../../../github.com/ebirukov/jserial

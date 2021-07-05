package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JwtPayload map[string]string

type JwtSignature []byte

func main() {
	var payload JwtPayload
	key := []byte("1234567890")

	header := JwtHeader{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerByte, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}
	payloadByte, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	hmac := hmac.New(sha256.New, key)
	_, err = hmac.Write(
		[]byte(
			fmt.Sprintf("%s.%s",
				base64.RawURLEncoding.EncodeToString(headerByte),
				base64.RawURLEncoding.EncodeToString(payloadByte),
			),
		),
	)
	if err != nil {
		panic(err)
	}
	signatureByte := hmac.Sum(nil)
	jwt := fmt.Sprintf("%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(headerByte),
		base64.RawURLEncoding.EncodeToString(payloadByte),
		base64.RawURLEncoding.EncodeToString(signatureByte),
	)
	fmt.Println(jwt)
}

package aesCbc

import (
	"encoding/base64"
)

type Base64Encoding struct {}

var Base64 Base64Encoding

func (encoding *Base64Encoding) NewEncrypter(key string, iv []byte) (*Encrypter, error) {
	binaryKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return NewEncrypter(binaryKey, iv)
}

func (encoding *Base64Encoding) Encrypt(sourceData []byte, key string) ([]byte, error) {
	binaryKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return Encrypt(sourceData, binaryKey)
}

func (encoding *Base64Encoding) EncryptToBase64(sourceData []byte, key string) (string, error) {
	binaryKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	return EncryptToBase64(sourceData, binaryKey)
}

func (encoding *Base64Encoding) NewDecrypter(key string, iv []byte) (*Decrypter, error) {
	binaryKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return NewDecrypter(binaryKey, iv)
}

func (encoding *Base64Encoding) Decrypt(encrData []byte, key string) ([]byte, error) {
	binaryKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return Decrypt(encrData, binaryKey)
}

func (encoding *Base64Encoding) DecryptFromBase64(encrString string, key string) ([]byte, error) {
	binaryKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return DecryptFromBase64(encrString, binaryKey)
}
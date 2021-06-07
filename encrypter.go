package aesCbc

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

type Encrypter struct {
	blockMode cipher.BlockMode
}

func NewEncrypter(key []byte, iv []byte) (*Encrypter, error) {
	encrypter := new(Encrypter)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, ErrInvalidIVLength
	}
	encrypter.blockMode = cipher.NewCBCEncrypter(block, iv)
	return encrypter, nil
}

func (encrypter *Encrypter) Encrypt(sourceData []byte) []byte {
	paddingData := Pkcs7Padding(sourceData)
	encrData := make([]byte, len(paddingData))
	encrypter.blockMode.CryptBlocks(encrData, paddingData)
	return encrData
}

func (encrypter *Encrypter) EncryptToBase64(sourceData []byte) string {
	encrData := encrypter.Encrypt(sourceData)
	return base64.StdEncoding.EncodeToString(encrData)
}

func Encrypt(sourceData []byte, key []byte) ([]byte, error) {
	encrypter, err := NewEncrypter(key, EmptyIV)
	if err != nil {
		return nil, err
	}
	return encrypter.Encrypt(sourceData), nil
}

func EncryptToBase64(sourceData []byte, key []byte) (string, error) {
	encrypter, err := NewEncrypter(key, EmptyIV)
	if err != nil {
		return "", err
	}
	return encrypter.EncryptToBase64(sourceData), nil
}

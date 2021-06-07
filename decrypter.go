package aesCbc

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

type Decrypter struct {
	blockMode cipher.BlockMode
}

func NewDecrypter(key []byte, iv []byte) (*Decrypter, error) {
	decrypter := new(Decrypter)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, ErrInvalidIVLength
	}
	decrypter.blockMode = cipher.NewCBCDecrypter(block, iv)
	return decrypter, nil
}

func (decrypter *Decrypter) Decrypt(encrData []byte) ([]byte, error) {
	if len(encrData) % aes.BlockSize != 0 {
		return nil, ErrInvalidEncrLength
	}
	paddingData := make([]byte, len(encrData))
	decrypter.blockMode.CryptBlocks(paddingData, encrData)
	return Pkcs7UnPadding(paddingData)
}

func (decrypter *Decrypter) DecryptFromBase64(encrString string) ([]byte, error) {
	encrData, err := base64.StdEncoding.DecodeString(encrString)
	if err != nil {
		return nil, err
	}
	return decrypter.Decrypt(encrData)
}

func Decrypt(encrData []byte, key []byte) ([]byte, error) {
	decrypter, err := NewDecrypter(key, EmptyIV)
	if err != nil {
		return nil, err
	}
	return decrypter.Decrypt(encrData)
}

func DecryptFromBase64(encrString string, key []byte) ([]byte, error) {
	decrypter, err := NewDecrypter(key, EmptyIV)
	if err != nil {
		return nil, err
	}
	return decrypter.DecryptFromBase64(encrString)
}
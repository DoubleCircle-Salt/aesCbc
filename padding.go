package aesCbc

import (
	"bytes"
	"crypto/aes"
)

func Pkcs7Padding(b []byte) []byte {
	n := aes.BlockSize - (len(b) % aes.BlockSize)
	pb := make([]byte, len(b) + n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
}

func Pkcs7UnPadding(b []byte) ([]byte, error) {
	length := len(b)
	unpadding := int(b[length-1])
	if unpadding > aes.BlockSize {
		return nil, ErrInvalidEncrPkcs7Padding
	}
	return b[:length-unpadding], nil
}
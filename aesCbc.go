package aesCbc

import (
	"crypto/aes"
	"errors"
	"fmt"
)

var (
	ErrInvalidIVLength = errors.New(fmt.Sprintf("IV length must equal block size[%d]", aes.BlockSize))
	ErrInvalidEncrLength = errors.New("input not full blocks")
	ErrInvalidEncrPkcs7Padding = errors.New("invalid pkcs7 padding")
	ErrInvalidKeyType = errors.New("key type must be string/[]byte")
)

var EmptyIV = make([]byte, aes.BlockSize)

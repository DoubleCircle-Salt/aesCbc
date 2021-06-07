package aesCbc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

const (
	TEST_TIMES = 5
)

var (
	iv = make([]byte, 16)
)

func randBuffer() []byte {
	buffer := make([]byte, 16)
	rand.Read(buffer)
	return buffer
}

func testEncryptAndDecrypt(t *testing.T) {
	key := randBuffer()
	aesEncrypter, err := NewEncrypter(key, iv)
	if err != nil {
		t.Error(err)
		return
	}
	src := []byte("1234567890123456")
	encr := aesEncrypter.Encrypt(src)
	if string(encr) == "" {
		t.Error("Encrypt failed")
		return
	}
	aesDecrypter, err := NewDecrypter(key, iv)
	if err != nil {
		t.Error(err)
		return
	}
	res, err := aesDecrypter.Decrypt(encr)
	if err != nil {
		t.Error(err)
		return
	}
	if len(res) != len(src) || bytes.Compare(src, res) != 0 {
		t.Error("test failed")
		return
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	for i := 0; i < TEST_TIMES; i++ {
		testEncryptAndDecrypt(t)
	}
}

func testEncryptAndDecryptBase64(t *testing.T) {
	key := randBuffer()
	aesEncrypter, err := Base64.NewEncrypter(base64.StdEncoding.EncodeToString(key), iv)
	if err != nil {
		t.Error(err)
		return
	}
	src := []byte("1234567890123456789")
	encr := aesEncrypter.EncryptToBase64(src)
	if encr == "" {
		t.Error("Encrypt failed")
		return
	}
	aesDecrypter, err := Base64.NewDecrypter(base64.StdEncoding.EncodeToString(key), iv)
	if err != nil {
		t.Error(err)
		return
	}
	res, err := aesDecrypter.DecryptFromBase64(encr)
	if err != nil {
		t.Error(err)
		return
	}
	if len(res) != len(src) || bytes.Compare(src, res) != 0 {
		t.Error("test failed")
		return
	}
}

func TestEncryptAndDecryptBase64(t *testing.T) {
	for i := 0; i < TEST_TIMES; i++ {
		testEncryptAndDecryptBase64(t)
	}
}

func testDirect(t *testing.T) {
	key := randBuffer()
	src := []byte("1234567890123456789")
	encr, _ := Base64.EncryptToBase64(src, base64.StdEncoding.EncodeToString(key))
	if encr == "" {
		t.Error("Encrypt failed")
		return
	}
	res, err := Base64.DecryptFromBase64(encr, base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Error(err)
		return
	}
	if len(res) != len(src) || bytes.Compare(src, res) != 0 {
		t.Error("test failed")
		return
	}
}

func TestDirect(t * testing.T) {
	for i := 0; i < TEST_TIMES; i++ {
		testDirect(t)
	}
}
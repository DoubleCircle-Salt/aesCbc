package main

import (
    "encoding/base64"
    "fmt"
    "github.com/DoubleCircle-Salt/aesCbc"
)

func main(){
    key := []byte("1234567890123456")
    keyBase64 := base64.StdEncoding.EncodeToString(key)

    // encrypt
    encr, err := aesCbc.Base64.EncryptToBase64([]byte("teststring"), keyBase64)
    if err != nil {
        fmt.Println("encrypt failed: ", err)
    }
    // decrypt
    src, err := aesCbc.DecryptFromBase64(encr, key)
    if err != nil {
        fmt.Println("decrypt failed: ", err)
    }
    fmt.Println("decrypt: ", string(src))
}
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func decryptKey(key []byte, password string) ([]byte, error) {
	block, rest := pem.Decode(key)
	if len(rest) > 0 {
		log.Println("extra data included in key")
		return nil, errors.New("extra data included in key")
	}
	if !x509.IsEncryptedPEMBlock(block) {
		return key, nil
	}
	der, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		log.Println(fmt.Sprintf("decrypt failed: %v", err))
		return nil, fmt.Errorf("decrypt failed: %v", err)
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: block.Type, Bytes: der})
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf(err.Error())
	}
	return buf.Bytes(), nil
}

func main() {
	// read key file
	keyFile, err := os.ReadFile("server.key")
	check(err)
	log.Println(string(keyFile))
	// decrypt key file
	key, err := decryptKey(keyFile, "mypassword")
	check(err)
	log.Println(string(key))
}

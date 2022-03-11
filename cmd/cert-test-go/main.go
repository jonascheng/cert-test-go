package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
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

func loadCertificateByte(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(keyFileName string) []byte {
	// read key file
	keyFile, err := os.ReadFile(keyFileName)
	check(err)
	log.Println(string(keyFile))
	// decrypt key file
	key, err := decryptKey(keyFile, "mypassword")
	check(err)
	log.Println(string(key))
	return key
}

func readCert(certFileName string) []byte {
	// read cert file
	certFile, err := os.ReadFile(certFileName)
	check(err)
	log.Println(string(certFile))
	certInfo, err := loadCertificateByte(certFile)
	check(err)
	if certInfo.NotAfter.Unix() < time.Now().Unix() {
		log.Println("invalid certificate")
	}
	return certFile
}

func main() {
	key := readKey("server.key")
	cert := readCert("server.crt")
	_, err := tls.X509KeyPair(cert, key)
	check(err)
}

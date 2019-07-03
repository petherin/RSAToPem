// From https://medium.com/@raul_11817/export-import-pem-files-in-go-67614624adc7
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}

	// Generate public key
	publicKey := &privateKey.PublicKey
	fmt.Println("Private Key: ", privateKey)
	fmt.Println("Public key: ", publicKey)

	err = SavePrivateKeyPEM(privateKey)

	err = SavePublicKeyPEM(publicKey)

	OpenPrivateKeyPEM()

	publicKey = &privateKey.PublicKey
	fmt.Println("Private Key: ", privateKey)
	fmt.Println("Public key: ", publicKey)

}

func OpenPrivateKeyPEM() {
	// Open the PEM file
	privateKeyFile, err := os.Open("private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Read in PEM file and decode the buffer content
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()
	// Parse bytes to X509 private key
	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Private Key : ", privateKeyImported)
}

func SavePublicKeyPEM(publicKey *rsa.PublicKey) error {
	// Create empty file for public key PEM
	pemPublicFile, err := os.Create("public_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Create private key PEM block
	var pemPublicBlock = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}
	// Save to PEM file
	err = pem.Encode(pemPublicFile, pemPublicBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPublicFile.Close()
	return err
}

func SavePrivateKeyPEM(privateKey *rsa.PrivateKey) error {
	// Create empty file for private key PEM
	pemPrivateFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Create private key PEM block
	var pemPrivateBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	// Save to PEM file
	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPrivateFile.Close()
	return err
}
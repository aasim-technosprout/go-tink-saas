package main

import (
	"crypto/rand"
	"salesforce/sfdc"

	"golang.org/x/crypto/scrypt"
)

func main() {
	// Create a Salesforce client.
	client, err := sfdc.NewClient("username", "password", "instance_url")
	if err != nil {
		panic(err)
	}

	// Generate a random salt.
	salt := make([]byte, 32)
	rand.Read(salt)

	// Encrypt the data.
	encryptedData, err := scrypt.Key([]byte("my data"), salt, 16384, 8, 1, 32)
	if err != nil {
		panic(err)
	}

	// Save the encrypted data to Salesforce.
	err = client.SaveEncryptedData("encrypted_data", encryptedData)
	if err != nil {
		panic(err)
	}
}

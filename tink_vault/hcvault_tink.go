package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"time"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/integration/hcvault"
	"github.com/google/tink/go/keyset"
)

// The fake KMS should only be used in tests. It is not secure.
const keyURI = "hcvault://34.27.255.165:8200/transit/keys/payment"

func main() {
	// Get a KEK (key encryption key) AEAD. This is usually a remote AEAD to a KMS. In this example,
	// we use a fake KMS to avoid making RPCs.
	client, err := hcvault.NewClient(keyURI, tlsConfig(), vaultToken())
	if err != nil {
		log.Fatal(err)
	}
	kekAEAD, err := client.GetAEAD(keyURI)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println("KekeAED Keys", kekAEAD)

	// Generate a new keyset handle for the primitive we want to use.
	newHandle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println("NewHandle", newHandle)

	// Choose some associated data. This is the context in which the keyset will be used.
	keysetAssociatedData := []byte("keyset encryption example")

	// Encrypt the keyset with the KEK AEAD and the associated data.
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = newHandle.WriteWithAssociatedData(writer, kekAEAD, keysetAssociatedData)
	if err != nil {
		log.Fatal(err)
	}
	encryptedKeyset := buf.Bytes()

	// The encrypted keyset can now be stored.

	// To use the primitive, we first need to decrypt the keyset. We use the same
	// KEK AEAD and the same associated data that we used to encrypt it.
	reader := keyset.NewBinaryReader(bytes.NewReader(encryptedKeyset))
	handle, err := keyset.ReadWithAssociatedData(reader, kekAEAD, keysetAssociatedData)
	if err != nil {
		log.Fatal(err)
	}

	// Get the primitive.
	primitive, err := aead.New(handle)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive.
	plaintext := []byte("message")

	//plaintext print
	fmt.Println("plaintext:", string(plaintext))
	time.Sleep(2 * time.Second)
	fmt.Println("Now Encrypting")

	associatedData := []byte("example encryption")
	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	// check ciphertext
	fmt.Println("CipherText:", string(ciphertext))

	time.Sleep(2 * time.Second)
	fmt.Println("Now decrypting")

	decrypted, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Decrypted text:", string(decrypted))
	// Output: message
}

func tlsConfig() *tls.Config {
	// Return a TLS configuration used to communicate with Vault server via HTTPS.
	cfg := &tls.Config{}
	cfg.InsecureSkipVerify = true
	return cfg
}

func vaultToken() string {
	return "hvs.RHsogfbSSR6XPdLOMUxgWxCe" // Your Vault token.
}

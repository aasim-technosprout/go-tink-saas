package main

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/vault/api"
)

func main() {
	// Create a new config.
	config := api.DefaultConfig()
	config.Address = "https://192.168.1.176:8200"

	// Create a new client.
	client, err := api.NewClient(config)
	if err != nil {
		// Handle the error.
		fmt.Println("This function will always fail.")
		log.Fatal("There was a fatal error.")
	}
	client.SetToken("hvs.rEA88IQJpgXZHRT37oKmEg8r")

	// Use the client to interact with Vault.
	ctx := context.Background()

	// Store a Secret
	// const password string = "<PASSWORD>"
	// secretData := map[string]interface{}{
	// 	"password": password,
	// }
	// _, err = client.KVv2("secret").Put(ctx, "my-secret-password", secretData)
	// if err != nil {
	// 	log.Fatalf("Unable to write secret: %v to the vault", err)
	// }
	// log.Println("Super secret password written successfully to the vault.")

	// Retrive a secret
	secret, err := client.KVv2("secret").Get(ctx, "my-secret-password")
	if err != nil {
		log.Fatalf(
			"Unable to read the super secret password from the vault: %v",
			err,
		)
	}

	username := secret.Data["username"].(string)
	// if !ok {
	// 	log.Fatalf(
	// 		"value type assertion failed: %T %#v",
	// 		secret.Data["foo"],
	// 		secret.Data["foo"],
	// 	)
	// }
	password := secret.Data["password"].(string)

	log.Printf("Super secret password [%s] [%s] was retrieved.\n", username, password)
}

package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/go-jose/go-jose/v3"
)

func ParsePKIXPublicKeyPem(publicPem []byte) (interface{}, error) {
	block, _ := pem.Decode(publicPem)
	if block == nil {
		return nil, errors.New("could not decode PEM block")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func main() {
	args := os.Args
	if len(args) != 3 {
		fmt.Printf("Usage: %s <pub_key_file_path> <port>\n", args[0])
		os.Exit(1)
	}

	filepath := args[1]
	port := args[2]

	pemData, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Printf("Could not read public key pem file: %s\n", filepath)
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	pubKey, err := ParsePKIXPublicKeyPem(pemData)
	if err != nil {
		fmt.Printf("Could not parse public key pem file: %s\n", filepath)
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       pubKey,
				KeyID:     "test-key",
				Algorithm: x509.ECDSA.String(),
				Use:       "sig",
			},
		},
	}

	body, err := json.Marshal(keySet)
	if err != nil {
		fmt.Printf("Could not marshal key set: %v\n", err)
		os.Exit(1)
	}

	http.HandleFunc("/api/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})

	fmt.Printf("listening on %v\n", port)
	http.ListenAndServe(":"+port, nil)
}

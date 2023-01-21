package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"
)

const (
	tokenLength = 16
	expiry      = 24 * time.Hour
	secret      = "secret-key"
)

func generateCanaryToken() (string, error) {
	// Generate a random token
	token := make([]byte, tokenLength)
	_, err := io.ReadFull(rand.Reader, token)
	if err != nil {
		return "", fmt.Errorf("error generating token: %v", err)
	}

	// Hash the token with a secret key
	h := sha256.New()
	h.Write([]byte(secret))
	h.Write(token)
	hash := h.Sum(nil)

	// Encode the token in base64
	encodedToken := base64.StdEncoding.EncodeToString(hash)

	return encodedToken, nil
}

func checkCanaryToken(token string) bool {
	// Decode the token from base64
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		fmt.Println("Invalid token")
		return false
	}

	// Hash the token with the secret key and check if it matches the decoded token
	h := sha256.New()
	h.Write([]byte(secret))
	h.Write(decodedToken)
	hash := h.Sum(nil)

	if string(hash) == token {
		fmt.Println("Token is valid")
		return true
	}
	fmt.Println("Invalid token")
	return false
}

func main() {
	// Generate a new canary token
	token, err := generateCanaryToken()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("New canary token:", token)

	// Check if a token is valid
	valid := checkCanaryToken(token)
	fmt.Println("Token is valid:", valid)
}

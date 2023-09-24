package rutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func encrypt(plainText, password string) (string, error) {
	// Generate a 256-bit key from the password using SHA-256
	key := sha256.Sum256([]byte(password))

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	// Generate a random nonce (IV) for GCM encryption
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Create a GCM mode cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the plaintext
	cipherText := aesGCM.Seal(nil, nonce, []byte(plainText), nil)

	// Combine nonce and ciphertext and convert to hexadecimal
	encryptedText := append(nonce, cipherText...)
	return hex.EncodeToString(encryptedText), nil
}

func decrypt(encryptedText, password string) (string, error) {
	// Generate a 256-bit key from the password using SHA-256
	key := sha256.Sum256([]byte(password))

	// Decode the hexadecimal representation of the encrypted text
	encryptedBytes, err := hex.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	// Split the nonce and ciphertext
	nonce := encryptedBytes[:12]
	ciphertext := encryptedBytes[12:]

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	// Create a GCM mode cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Decrypt the ciphertext
	plainText, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func GetEnvironmentVariable(varname string) string {
	//Loads the .env file and throws an error if it cannot load the variables from that file correctly
	err := godotenv.Load(".env")
	if err != nil {
		panic(fmt.Errorf("Unable to load environment variables from .env file. Error:\n%v\n", err))
	}

	if err != nil {
		panic(err)
	}

	return os.Getenv(varname)
}

func SaveEnvironmentVariable(varname string, data string) error {
	//Loads the .env file and throws an error if it cannot load the variables from that file correctly
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err)
	}

	return os.Setenv(varname, data)

}

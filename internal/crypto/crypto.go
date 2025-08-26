package crypto

import (
	"os"
	"strconv"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword gera o hash de uma senha usando bcrypt
func HashPassword(password string) (string, error) {
	cost := bcrypt.DefaultCost
	if envCost := os.Getenv("BCRYPT_COST"); envCost != "" {
		if parsed, err := strconv.Atoi(envCost); err == nil && parsed >= bcrypt.MinCost && parsed <= bcrypt.MaxCost {
			cost = parsed
		}
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(bytes), err
}

// CheckPasswordHash compara uma senha com seu hash
func CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// getEncryptionKey retorna a chave de criptografia do ambiente
func getEncryptionKey() ([]byte, error) {
	key := os.Getenv("DATA_ENCRYPTION_KEY")
	if len(key) != 32 {
		return nil, errors.New("DATA_ENCRYPTION_KEY deve ter 32 bytes")
	}
	return []byte(key), nil
}

// Encrypt criptografa texto plano usando AES-GCM
func Encrypt(plainText string) (string, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt decriptografa texto cifrado usando AES-GCM
func Decrypt(cipherText string) (string, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("cipherText muito curto")
	}
	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

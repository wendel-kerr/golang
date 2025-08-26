package integrations_test

import (
	"api-vault/internal/crypto"
	"testing"
)

func TestIntegrationEncryptDecrypt(t *testing.T) {
	// Simula o fluxo de criptografia/decriptografia de ClientSecret
	key := "12345678901234567890123456789012"
	t.Setenv("DATA_ENCRYPTION_KEY", key)
	secret := "meu-segredo-super-seguro"
	cipher, err := crypto.Encrypt(secret)
	if err != nil {
		t.Fatalf("Erro ao criptografar ClientSecret: %v", err)
	}
	plain, err := crypto.Decrypt(cipher)
	if err != nil {
		t.Fatalf("Erro ao decriptografar ClientSecret: %v", err)
	}
	if plain != secret {
		t.Errorf("ClientSecret decriptografado diferente do original: got %s, want %s", plain, secret)
	}
}

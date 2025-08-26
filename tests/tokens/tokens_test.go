package tokens_test

import (
	"api-vault/internal/crypto"
	"testing"
)

func TestTokenEncryptDecrypt(t *testing.T) {
	// Simula o fluxo de criptografia/decriptografia de AccessToken e RefreshToken
	key := "12345678901234567890123456789012"
	t.Setenv("DATA_ENCRYPTION_KEY", key)
	access := "access-token-super-seguro"
	refresh := "refresh-token-super-seguro"
	cipherAccess, err := crypto.Encrypt(access)
	if err != nil {
		t.Fatalf("Erro ao criptografar AccessToken: %v", err)
	}
	cipherRefresh, err := crypto.Encrypt(refresh)
	if err != nil {
		t.Fatalf("Erro ao criptografar RefreshToken: %v", err)
	}
	plainAccess, err := crypto.Decrypt(cipherAccess)
	if err != nil {
		t.Fatalf("Erro ao decriptografar AccessToken: %v", err)
	}
	plainRefresh, err := crypto.Decrypt(cipherRefresh)
	if err != nil {
		t.Fatalf("Erro ao decriptografar RefreshToken: %v", err)
	}
	if plainAccess != access {
		t.Errorf("AccessToken decriptografado diferente do original: got %s, want %s", plainAccess, access)
	}
	if plainRefresh != refresh {
		t.Errorf("RefreshToken decriptografado diferente do original: got %s, want %s", plainRefresh, refresh)
	}
}

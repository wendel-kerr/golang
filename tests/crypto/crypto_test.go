package crypto_test

import (
	"api-vault/internal/crypto"
	"os"
	"testing"
)

func TestHashPassword_DefaultCost(t *testing.T) {
	os.Unsetenv("BCRYPT_COST")
	hash, err := crypto.HashPassword("senha123")
	if err != nil {
		t.Fatalf("Erro ao gerar hash: %v", err)
	}
	if !crypto.CheckPasswordHash("senha123", hash) {
		t.Error("Hash não corresponde à senha original")
	}
}

func TestHashPassword_CustomCost(t *testing.T) {
	os.Setenv("BCRYPT_COST", "12")
	hash, err := crypto.HashPassword("senha123")
	if err != nil {
		t.Fatalf("Erro ao gerar hash com custo customizado: %v", err)
	}
	if !crypto.CheckPasswordHash("senha123", hash) {
		t.Error("Hash não corresponde à senha original com custo customizado")
	}
	os.Unsetenv("BCRYPT_COST")
}

func TestHashPassword_InvalidCost(t *testing.T) {
	os.Setenv("BCRYPT_COST", "999") // valor inválido
	hash, err := crypto.HashPassword("senha123")
	if err != nil {
		t.Fatalf("Erro ao gerar hash com custo inválido: %v", err)
	}
	if !crypto.CheckPasswordHash("senha123", hash) {
		t.Error("Hash não corresponde à senha original com custo inválido")
	}
	os.Unsetenv("BCRYPT_COST")
}

func TestEncryptDecrypt_Success(t *testing.T) {
	os.Setenv("DATA_ENCRYPTION_KEY", "12345678901234567890123456789012") // 32 bytes
	original := "segredo-super-seguro"
	cipher, err := crypto.Encrypt(original)
	if err != nil {
		t.Fatalf("Erro ao criptografar: %v", err)
	}
	plain, err := crypto.Decrypt(cipher)
	if err != nil {
		t.Fatalf("Erro ao decriptografar: %v", err)
	}
	if plain != original {
		t.Errorf("Texto decriptografado diferente do original: got %s, want %s", plain, original)
	}
	os.Unsetenv("DATA_ENCRYPTION_KEY")
}

func TestEncryptDecrypt_InvalidKey(t *testing.T) {
	os.Setenv("DATA_ENCRYPTION_KEY", "short-key") // inválido
	_, err := crypto.Encrypt("teste")
	if err == nil {
		t.Error("Esperado erro de chave inválida na criptografia")
	}
	os.Unsetenv("DATA_ENCRYPTION_KEY")
}

func TestDecrypt_InvalidCipher(t *testing.T) {
	os.Setenv("DATA_ENCRYPTION_KEY", "12345678901234567890123456789012")
	_, err := crypto.Decrypt("texto-invalido-base64")
	if err == nil {
		t.Error("Esperado erro ao decriptografar texto inválido")
	}
	os.Unsetenv("DATA_ENCRYPTION_KEY")
}

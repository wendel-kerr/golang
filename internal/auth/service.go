package auth

import (
	"api-vault/internal/crypto"
	"errors"

	"gorm.io/gorm"
)

// AuthenticateUser valida usuário/senha e retorna o usuário se válido
func AuthenticateUser(conn *gorm.DB, username, password string) (*User, error) {
	var user User
	result := conn.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, errors.New("usuário não encontrado")
	}
	// Compara o hash da senha usando pacote crypto
	if !crypto.CheckPasswordHash(password, user.Password) {
		return nil, errors.New("senha incorreta")
	}
	return &user, nil
}

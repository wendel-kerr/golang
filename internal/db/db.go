package db

import (
	"api-vault/internal/audit"
	"api-vault/internal/auth"
	"api-vault/internal/integrations"
	"api-vault/internal/tokens"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Init() (*gorm.DB, error) {
	dsn := os.Getenv("POSTGRES_DSN")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	// Migração de todos os modelos
	if err := db.AutoMigrate(&integrations.Integration{}, &tokens.Token{}, &auth.User{}, &audit.AuditLog{}); err != nil {
		log.Fatal("Erro ao migrar tabelas:", err)
	}
	DB = db
	return db, nil
}

package tokens

import (
	"time"

	"gorm.io/gorm"
)

type Token struct {
	ID            uint      `gorm:"primaryKey"`
	IntegrationID uint      `gorm:"index"`
	AccessToken   string    `gorm:"not null"`
	RefreshToken  string    `gorm:"not null"`
	ExpiresAt     time.Time `gorm:"not null"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     gorm.DeletedAt `gorm:"index"`
}

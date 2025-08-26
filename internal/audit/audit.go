package audit

import (
	"time"

	"gorm.io/gorm"
)

type AuditLog struct {
	ID        uint      `gorm:"primaryKey"`
	Timestamp time.Time `gorm:"autoCreateTime"`
	User      string    // usuário responsável (se aplicável)
	Action    string    // ação realizada
	Status    string    // OK ou FAIL
	Details   string    // detalhes do evento
}

func SaveAuditLog(db *gorm.DB, user, action, status, details string) error {
	log := AuditLog{
		User:    user,
		Action:  action,
		Status:  status,
		Details: details,
	}
	return db.Create(&log).Error
}

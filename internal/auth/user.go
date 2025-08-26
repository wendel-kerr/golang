package auth

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"not null;unique"`
	Password string `gorm:"not null"`
	Role     string `gorm:"not null"` // admin, user
}

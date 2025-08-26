package integrations

type Integration struct {
	ID           uint   `gorm:"primaryKey"`
	Name         string `gorm:"not null;unique"`
	AuthType     string `gorm:"not null"`
	ClientID     string `gorm:"not null"`
	ClientSecret string `gorm:"not null"`
	TokenURL     string `gorm:"not null"`
}

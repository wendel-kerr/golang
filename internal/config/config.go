package config

import (
	"github.com/spf13/viper"
)

func GetPostgresDSN() string {
	viper.SetDefault("POSTGRES_DSN", "postgres://user:password@localhost:5432/dbname?sslmode=disable")
	viper.AutomaticEnv()
	return viper.GetString("POSTGRES_DSN")
}

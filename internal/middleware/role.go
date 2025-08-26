package middleware

import (
	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

// IsAdmin verifica se o usuário autenticado é admin
func IsAdmin(c *gin.Context) bool {
	claims := jwt.ExtractClaims(c)
	role, _ := claims["role"].(string)
	return role == "admin"
}

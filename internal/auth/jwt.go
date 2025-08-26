package auth

import (
	"time"

	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

var IdentityKey = "id"

// JWTMiddlewareWithDB recebe a instância do banco e retorna o middleware JWT
func JWTMiddlewareWithDB(conn *gorm.DB) (*jwt.GinJWTMiddleware, error) {
	viper.AutomaticEnv()
	jwtKey := viper.GetString("JWT_SECRET")
	if jwtKey == "" {
		jwtKey = "changeme" // fallback seguro para dev
	}
	return jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "api zone",
		Key:         []byte(jwtKey),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: IdentityKey,
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals Login
			if err := c.ShouldBindJSON(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			user, err := AuthenticateUser(conn, loginVals.Username, loginVals.Password)
			if err != nil {
				return nil, jwt.ErrFailedAuthentication
			}
			return user, nil
		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if u, ok := data.(*User); ok {
				return jwt.MapClaims{
					IdentityKey: u.ID,
					"username":  u.Username,
					"role":      u.Role,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			role, _ := claims["role"].(string)
			return &User{ID: uint(claims[IdentityKey].(float64)), Username: claims["username"].(string), Role: role}
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if _, ok := data.(*User); ok {
				return true
			}
			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{"error": message})
		},
		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})
}

// Login struct para autenticação
type Login struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Função auxiliar para verificar se o usuário autenticado é admin
func IsAdmin(c *gin.Context) bool {
	claims := jwt.ExtractClaims(c)
	role, _ := claims["role"].(string)
	return role == "admin"
}

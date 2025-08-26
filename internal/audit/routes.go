// @Summary Consultar logs de auditoria
// @Description Lista os logs de auditoria com filtros e paginação
// @Tags auditoria
// @Produce json
// @Param user query string false "Usuário"
// @Param action query string false "Ação"
// @Param status query string false "Status"
// @Param start query string false "Data inicial (RFC3339)"
// @Param end query string false "Data final (RFC3339)"
// @Param page query int false "Página"
// @Param page_size query int false "Itens por página"
// @Success 200 {array} AuditLog
// @Failure 403,500 {object} gin.H
// @Router /audit-logs [get]
package audit

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func RegisterRoutes(r *gin.Engine, conn *gorm.DB) {
	r.GET("/audit-logs", func(c *gin.Context) {
		// Protege endpoint: apenas admin
		role, _ := c.Get("role")
		if role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Acesso permitido apenas para admin"})
			return
		}

		// Filtros
		user := c.Query("user")
		action := c.Query("action")
		status := c.Query("status")
		start := c.Query("start") // data inicial (RFC3339)
		end := c.Query("end")     // data final (RFC3339)
		page := c.DefaultQuery("page", "1")
		pageSize := c.DefaultQuery("page_size", "50")

		var logs []AuditLog
		dbq := conn.Model(&AuditLog{})
		if user != "" {
			dbq = dbq.Where("user = ?", user)
		}
		if action != "" {
			dbq = dbq.Where("action = ?", action)
		}
		if status != "" {
			dbq = dbq.Where("status = ?", status)
		}
		if start != "" {
			dbq = dbq.Where("timestamp >= ?", start)
		}
		if end != "" {
			dbq = dbq.Where("timestamp <= ?", end)
		}
		// Paginação
		var p, ps int
		fmt.Sscanf(page, "%d", &p)
		fmt.Sscanf(pageSize, "%d", &ps)
		if p < 1 {
			p = 1
		}
		if ps < 1 || ps > 200 {
			ps = 50
		}
		offset := (p - 1) * ps
		if err := dbq.Order("timestamp desc").Offset(offset).Limit(ps).Find(&logs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, logs)
	})
}

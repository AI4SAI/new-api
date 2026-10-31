package middleware

import (
	"errors"
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func ManagedAccountAuthorization(operation string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := service.AuthorizeManagedAccount(c, operation); err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, service.ErrManagedAccountDenied) {
				status = http.StatusForbidden
			}
			common.ApiErrorStatus(c, status, common.NewMessage("Managed account access is unavailable"))
			c.Abort()
			return
		}
		if account := service.ManagementAccount(c); account != nil && operation == "model.usage.read" {
			visibility, err := model.UserTokenLogVisibility(account.OwnerID)
			if err != nil {
				common.ApiErrorStatus(c, http.StatusServiceUnavailable, common.NewMessage("Managed account access is unavailable"))
				c.Abort()
				return
			}
			c.Set("management_token_visibility", visibility)
		}
		c.Next()
	}
}

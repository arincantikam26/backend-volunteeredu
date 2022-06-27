package api

import (
	"net/http"

	"github.com/arincantikam26/volunteeredu/repository"
	"github.com/gin-gonic/gin"
)

type RoleResponse struct {
	ID     int    `json:"role_act_id"`
	Detail string `json:"detail"`
}

func (api *API) GetRoles(c *gin.Context) {
	// api.AllowOrigin(c)
	roles, err := api.roleRepo.GetRole()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}
	var rolesResponse []RoleResponse
	for _, v := range roles {
		roleResponse := convertToRoleResponse(v)
		rolesResponse = append(rolesResponse, roleResponse)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rolesResponse,
	})
}

func convertToRoleResponse(role repository.Role) RoleResponse {
	return RoleResponse{
		ID:     role.ID,
		Detail: role.Detail,
	}
}

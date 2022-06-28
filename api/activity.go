package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type ChooseRoleResponse struct {
	ID        int `json:"activity_id"`
	UserID    int `json:"user_id"`
	ClassID   int `json:"class_id"`
	RoleActID int `json:"role_act"`
}

func (api *API) ChooseRole(c *gin.Context) {
	var chooseRole ChooseRoleResponse
	if err := c.ShouldBindJSON(&chooseRole); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}
	token, err := c.Request.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			c.JSON(http.StatusUnauthorized, gin.H{"Error": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tokenString := token.Value

	userId, err := api.usersRepo.GetUserIDByToken(tokenString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
	}

	chooseRole.UserID = *userId

	res, err := api.activityRepo.ChooseRole(chooseRole.UserID, chooseRole.ClassID, chooseRole.RoleActID)

	if res == nil && err == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": "This class is already in your activity!"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status code": http.StatusOK,
		"message":     "Success Memilih Kelas!",
	})
}

func (api *API) GetMyActivity(c *gin.Context) {
	userID := c.Param("id")
	userIDInt, _ := strconv.Atoi(userID)
	res, err := api.activityRepo.FetchActivityByID(userIDInt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}
	if res == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": "No activity",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": res,
	})
}

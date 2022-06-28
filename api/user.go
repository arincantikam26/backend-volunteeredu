package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/arincantikam26/volunteeredu/repository"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

type UserResponse struct {
	ID        int    `json:"user_id"`
	Fullname  string `json:"full_name"`
	Email     string `json:"email"`
	DateBirth string `json:"date_birth"`
	Phone     string `json:"phone"`
	Address   string `json:"address"`
	Password  string `json:"password"`
	RoleID    int    `json:"role_user_id"`
}

type Config struct {
	ValidateHeaders bool
	Origins         string
	RequestHeaders  string
	ExposedHeaders  string
	Methods         string
	MaxAge          time.Duration
	Credentials     bool
}

type StatusResponse struct {
	StatusCode    int    `json:"status_code"`
	StatusMessage string `json:"status_message"`
}

func (api *API) GetUsers(c *gin.Context) {
	users, err := api.usersRepo.FetchUsers()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": err})
		return
	}

	var usersResponse []UserResponse

	for _, v := range users {
		userResponse := convertToUserResponse(v)

		usersResponse = append(usersResponse, userResponse)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": usersResponse,
	})
}

func (api *API) GetUserByID(c *gin.Context) {
	idString := c.Param("id")
	id, _ := strconv.Atoi(idString)

	result, err := api.usersRepo.FetchUserByID(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": err})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": result,
	})

}
func (api *API) PostUserRegist(c *gin.Context) {
	var user repository.UserRequest

	if err := c.ShouldBindJSON(&user); err != nil {
		errorMessages := []string{}
		for _, e := range err.(validator.ValidationErrors) {
			errorMessage := fmt.Sprintf("Error on field %s, condition: %s", e.Field(), e.ActualTag())
			errorMessages = append(errorMessages, errorMessage)
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": errorMessages,
		})
		return

	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 8)

	res, err := api.usersRepo.InsertUser(user.Fullname, user.Email, user.DateBirth, string(hashedPassword), user.Phone, user.Address)
	if res == nil && err == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status code": http.StatusBadRequest,
			"message":     "Email Has Registered!",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status code": http.StatusOK,
		"message":     "Welcome, Success registered!",
	})

}

func convertToUserResponse(h repository.User) UserResponse {
	return UserResponse{
		ID:        h.ID,
		Fullname:  h.Fullname,
		Email:     h.Email,
		DateBirth: h.DateBirth,
		Password:  h.Password,
		Phone:     h.Phone,
		Address:   h.Address,
		RoleID:    h.RoleID,
	}
}

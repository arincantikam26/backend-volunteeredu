package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Email     string    `json:"email"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Token struct {
	UserId    int       `json:"user_id" binding:"required"`
	Token     string    `json:"token" binding:"required"`
	ExpiresAt time.Time `json:"expires_at" binding:"required"`
}

type AuthErrorResponse struct {
	Error string `json:"error"`
}

var jwtKey = []byte("secret")

type Claims struct {
	Email string
	Role  string
	jwt.StandardClaims
}

func (api *API) LoginUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	pass, err := api.usersRepo.GetPasswordCompare(user.Email)
	if err != nil {
		if err == sqlite3.ErrConstraintRowID {
			c.JSON(http.StatusUnauthorized, gin.H{"Error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "e-mail is not registered!"})
		return
	}

	compareVal := bcrypt.CompareHashAndPassword([]byte(*pass), []byte(user.Password))
	if compareVal != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "wrong password/password too short"})
		return
	}

	res, err := api.usersRepo.LoginUser(user.Email, *pass)
	c.Header("Content-Type", "application/json")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	userRole, _ := api.usersRepo.FetchUserRole(*res)

	expirationTime := time.Now().Add(60 * time.Minute)

	claims := &Claims{
		Email: *res,
		Role:  *userRole,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	//encode claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
	}

	//push token to db auth when user logged in
	var pushtoken Token

	fetchUserId, _ := api.usersRepo.FetchUserIdByEmail(*res)

	pushtoken = Token{
		UserId:    *fetchUserId,
		Token:     tokenString,
		ExpiresAt: expirationTime,
	}

	tknToDb, err := api.usersRepo.PushToken(pushtoken.UserId, pushtoken.Token, pushtoken.ExpiresAt)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": err.Error()})
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
		Path:    ("/"),
	})

	c.JSON(http.StatusOK, gin.H{
		"status code:": http.StatusOK,
		"message":      "login successful",
		"data: ": LoginResponse{
			Email:     *res,
			Token:     *tknToDb,
			ExpiresAt: expirationTime,
		},
	})
}

func (api *API) GetUserID(c *gin.Context) {
	token, err := c.Cookie("token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	getUserId, err := api.usersRepo.GetUserIDByToken(token)
	if getUserId == nil || err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status code:": http.StatusOK,
		"message":      "get user id successful",
		"data":         getUserId,
	})

}

func (api *API) LogoutUser(c *gin.Context) {
	token, err := c.Request.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no cookie"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if token.Value == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no cookie"})
		return
	}
	api.usersRepo.DeleteToken(token.Value)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "token",
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})

	c.JSON(http.StatusOK, gin.H{
		"status code:": http.StatusOK,
		"message":      "logout successful",
	})
}

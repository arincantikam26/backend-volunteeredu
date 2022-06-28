package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "https://final-project-kelompok-74-rafiakbar13.vercel.app")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Access-Control-Allow-Origin, token, Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, Cache-Control, X-Requested-With, multipart/form-data")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			fmt.Println("OPTIONS")
			c.AbortWithStatus(204)
		}
		c.Next()
	}
}

func (api *API) AuthMiddleware(next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Request.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				c.JSON(http.StatusUnauthorized, gin.H{"Error4": err.Error()})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"Error5": err.Error()})
			return
		}

		tokenString := token.Value

		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{"Error1": err.Error()})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"Error2": err.Error()})
			return
		}

		if !tkn.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"Error3": err.Error()})
			c.Abort()
			return
		}
		ctx := context.WithValue(c.Request.Context(), "email", claims.Email)
		ctx = context.WithValue(ctx, "role", claims.Role)
		ctx = context.WithValue(ctx, "props", claims)
		c.Request = c.Request.WithContext(ctx)

		next(c)

	}
}

func (api *API) AdminMiddleware(next gin.HandlerFunc) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		role := c.Request.Context().Value("role")
		if role != "1" { //1 is admin
			c.JSON(http.StatusForbidden, gin.H{"Error": "Forbidden access"})
			c.Abort()
			return
		}
		next(c)
	})
}

func (api *API) GET(next gin.HandlerFunc) gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		if ctx.Request.Method != http.MethodGet {
			ctx.JSON(http.StatusMethodNotAllowed, gin.H{"Error": "Need GET Method!"})
			return
		}
		next(ctx)
	})
}

func (api *API) POST(next gin.HandlerFunc) gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		if ctx.Request.Method != http.MethodPost {
			ctx.JSON(http.StatusMethodNotAllowed, gin.H{"Error": "Need POST Method!"})
			return
		}
		next(ctx)
	})
}

func (api *API) DELETE(next gin.HandlerFunc) gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		if ctx.Request.Method != http.MethodDelete {
			ctx.JSON(http.StatusMethodNotAllowed, gin.H{"Error": "Need DELETE Method!"})
			return
		}
		next(ctx)
	})
}

func (api *API) PATCH(next gin.HandlerFunc) gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		if ctx.Request.Method != http.MethodPatch {
			ctx.JSON(http.StatusMethodNotAllowed, gin.H{"Error": "Need PATCH Method!"})
			return
		}
		next(ctx)
	})
}

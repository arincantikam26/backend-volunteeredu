package api

import (
	"fmt"

	"github.com/arincantikam26/volunteeredu/repository"
	"github.com/gin-gonic/gin"
)

type API struct {
	usersRepo    repository.UserRepository
	classRepo    repository.ClassRepository
	activityRepo repository.ActivityRepository
	galleryRepo  repository.GalleryRepository
	roleRepo     repository.RoleRepository
	gin          *gin.Engine
}

func NewAPI(usersRepo repository.UserRepository, classRepo repository.ClassRepository, activityRepo repository.ActivityRepository, galleryRepo repository.GalleryRepository, roleRepo repository.RoleRepository) API {
	gin := gin.Default()

	api := API{
		usersRepo, classRepo, activityRepo, galleryRepo, roleRepo, gin,
	}

	// gin.SetTrustedProxies([]string{"192.168.56.1"})
	gin.Use(CORSMiddleware())

	v1 := gin.Group("/api/v1")

	//LANDING PAGE
	v1.GET("/gallery/limit", api.GET(api.GetGalleryLimit))
	v1.GET("/class/limit", api.GET(api.GetClassLimit))

	//USERS
	v1.POST("/users/regist", api.POST(api.PostUserRegist))
	v1.POST("/users/login", api.POST(api.LoginUser))
	v1.GET("/users", api.GET(api.GetUsers))
	v1.GET("/users/:id", api.GET(api.GetUserByID))
	v1.GET("/users/token", api.GET(api.GetUserID))
	v1.POST("/users/logout", api.POST(api.LogoutUser))

	//CLASS_SCHEDULE
	v1.GET("/classes", api.GET(api.GetClasses))
	v1.GET("/classes/:id", api.GET(api.GetClassByID))
	v1.GET("/gallery", api.GET(api.GetGallery))

	//ACTIVITY
	v1.POST("/chooserole", api.POST(api.AuthMiddleware(api.ChooseRole)))
	v1.GET("/roles", api.GET(api.AuthMiddleware(api.GetRoles)))
	v1.GET("/myactivity/:id", api.GET(api.AuthMiddleware(api.GetMyActivity)))

	//// API with AuthMiddleware and AdminMiddleware
	v1.GET("/participate", api.GET(api.AuthMiddleware(api.AdminMiddleware(api.GetListParticipate))))
	v1.GET("/volunteer", api.GET(api.AuthMiddleware(api.AdminMiddleware(api.GetListVolunteer))))

	v1.POST("/add/class", api.POST(api.AuthMiddleware(api.AdminMiddleware(api.AddNewClass))))
	v1.PATCH("/class/update/:id", api.PATCH(api.AuthMiddleware(api.AdminMiddleware(api.UpdateClass))))
	v1.DELETE("/class/delete/:id", api.DELETE(api.AuthMiddleware(api.AdminMiddleware(api.DeleteClass))))

	v1.GET("/gallery/:id", api.GET(api.AuthMiddleware(api.AdminMiddleware(api.GetGalleryByID))))
	v1.POST("/gallery/add", api.POST(api.AuthMiddleware(api.AdminMiddleware(api.AddNewGallery))))
	v1.PATCH("/gallery/update/:id", api.PATCH(api.AuthMiddleware(api.AdminMiddleware(api.UpdateGallery))))
	v1.DELETE("/gallery/delete/:id", api.DELETE(api.AuthMiddleware(api.AdminMiddleware(api.DeleteGallery))))

	return api
}

func (api *API) Handler() *gin.Engine {
	return api.gin
}

func (api *API) Start() {
	fmt.Println("starting web server at https://localhost:8080/")
	api.Handler().Run()
}

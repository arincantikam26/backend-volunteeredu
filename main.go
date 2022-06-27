package main

import (
	"database/sql"

	"github.com/arincantikam26/volunteeredu/api"
	"github.com/arincantikam26/volunteeredu/repository"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", "database/VolunteerEdu.db")
	if err != nil {
		panic(err)
	}

	usersRepo := repository.NewUserRepository(db)
	classRepo := repository.NewClassRepository(db)
	activityRepo := repository.NewActivityRepository(db)
	galleryRepo := repository.NewGalleryRepo(db)
	roleRepo := repository.NewRoleRepository(db)

	mainAPI := api.NewAPI(*usersRepo, *classRepo, *activityRepo, *galleryRepo, *roleRepo)

	mainAPI.Start()

	// router.Use(cors.Default())

}

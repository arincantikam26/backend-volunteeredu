package repository_test

import (
	"database/sql"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/arincantikam26/volunteeredu/repository"
)

var _ = Describe("Repository", func() {
	var db *sql.DB
	var err error
	var usersRepo *repository.UserRepository
	var classRepo *repository.ClassRepository
	var galleryRepo *repository.GalleryRepository
	var activityRepo *repository.ActivityRepository

	BeforeEach(func() {
		db, err = sql.Open("sqlite3", "./VolunteerEdu.db")
		if err != nil {
			panic(err)
		}

		_, err = db.Exec(`

		CREATE TABLE IF NOT EXISTS role_user(
			role_user_id integer not null primary key AUTOINCREMENT,
			detail varchar(10) not null
		);
		
		CREATE TABLE IF NOT EXISTS class_schedules (
			class_id integer not null primary key AUTOINCREMENT,
			title varchar(255) not null,
			date date not null,
			time time not null,
			place varchar(255) not null,
			image varchar(255) not null,
			detail text not null
		);
	
		CREATE TABLE IF NOT EXISTS users(
			user_id integer not null primary key AUTOINCREMENT,
			full_name varchar(100) not null,
			email varchar(100) not null,
			date_birth date not null,
			password varchar not null,
			phone varchar(20) not null,
			address varchar not null,
			role_user_id integer DEFAULT 2,
			CONSTRAINT fk_role_user
				FOREIGN KEY (role_user_id)
				REFERENCES role_user(role_user_id)
		);
	
		CREATE TABLE IF NOT EXISTS activities(
			activity_id integer not null primary key AUTOINCREMENT,
			user_id integer DEFAULT 0,
			class_id integer DEFAULT 0,
			role_act_id integer DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(user_id),
			FOREIGN KEY (class_id) REFERENCES class_schedules(class_id),
			FOREIGN KEY (role_act_id) REFERENCES role_act(role_act_id)
		);
		
		CREATE TABLE IF NOT EXISTS gallery(
			gallery_id integer not null primary key AUTOINCREMENT,
			image varchar(255) not null,
			description text
		);
	
		CREATE TABLE IF NOT EXISTS auth(
			auth_id integer not null primary key AUTOINCREMENT,
			user_id integer,
			token varchar(255) not null,
			expired_at datetime not null,
			FOREIGN KEY (user_id) REFERENCES users(user_id)
	
		);
	
		CREATE TABLE IF NOT EXISTS role_act(
			role_act_id integer not null primary key AUTOINCREMENT,
			detail varchar(10) not null
		);
	
	
		INSERT INTO role_user(role_user_id, detail) VALUES 
			(1, 'admin'),
			(2, 'user');
	
		INSERT INTO role_act(role_act_id, detail) VALUES 
			(1, 'participant'),
			(2, 'volunteer');
		
		INSERT INTO users(user_id, full_name, email, date_birth, password, phone, address, role_user_id)
		VALUES 
			(1, 'admin', 'admin@gmail.com', '2000-01-01', '$2a$08$kWv/UoqnU171zHYFuG.krOM3iV85IhSxfuUSUN3rd0ucqWNTiFna2', '0762314210', 'jakarta', 1),
			(2, 'arin cantika', 'arin@gmail.com', '2001-11-26', '$2a$08$uTg/REjUvqvREzoXOgSHE.CdRA0ZKIpbqYKfIgDcKaaQ9olyh0RUK', '08116655801', 'padang', 2),
			(3, 'dewi sugianti', 'dewi@gmail.com', '2001-02-12', '$2a$08$BLc2qz8r0kwevR8Qwy6C0.r9FyNmG6mmzZfTC4BQtSRuJAhT6bTLi', '082299446963', 'jakarta', 2);
	
		INSERT INTO class_schedules(class_id, title, date, time, place, image, detail) 
		VALUES 
			(1, 'Kelas Coding', '2022-06-18', '16:00:00', 'UNJ Kampus B', 'coding.jpg', 'kelas coding ini dapat diikuti oleh semua umur'),
			(2, 'Kelas Menulis', '2022-06-18', '16:00:00', 'UNJ Kampus B', 'menulis.jpg', 'kelas menulis ini dapat diikuti oleh semua umur'),
			(3, 'Kelas Melukis', '2022-06-18', '16:00:00', 'UNJ Kampus B', 'melukis.jpg', 'kelas melukis ini dapat diikuti oleh semua umur'),
			(4, 'Kelas Membaca', '2022-06-18', '16:00:00', 'UNJ Kampus B', 'membaca.jpg', 'kelas membaca ini dapat diikuti oleh semua umur');
	
		INSERT INTO activities (activity_id, user_id, class_id, role_act_id) 
		VALUES (1, 2, 1, 1), (2, 3, 1, 2);
	
		INSERT INTO gallery (gallery_id, image, description)
		VALUES 	(1, 'gallery1.jpg', 'activity 1'),
				(2, 'gallery2.jpg', 'activity 2'),
				(3, 'gallery3.jpg', 'activity 3'),
				(4, 'gallery4.jpg', 'activity 4'),
				(5, 'gallery5.jpg', 'activity 5'),
				(6, 'gallery6.jpg', 'activity 6'),
				(7, 'gallery7.jpg', 'activity 7');
		`)

		if err != nil {
			panic(err)
		}

		usersRepo = repository.NewUserRepository(db)
		classRepo = repository.NewClassRepository(db)
		galleryRepo = repository.NewGalleryRepo(db)
		activityRepo = repository.NewActivityRepository(db)
	})
	AfterEach(func() {
		//Teardown
		db, err := sql.Open("sqlite3", "./VolunteerEdu.db")
		if err != nil {
			panic(err)
		}

		_, err = db.Exec(`
		DROP TABLE IF EXISTS activities;
		DROP TABLE IF EXISTS users;
		DROP TABLE IF EXISTS class_schedules;
		DROP TABLE IF EXISTS role_act;
		DROP TABLE IF EXISTS auth;
		DROP TABLE IF EXISTS gallery;
		DROP TABLE IF EXISTS role_user;`)

		if err != nil {
			panic(err)
		}
	})
	Describe("Select All Users", func() {
		When("get all user list from database", func() {
			It("should return all user list", func() {
				var email = []string{"admin@gmail.com", "arin@gmail.com", "dewi@gmail.com"}

				userList, err := usersRepo.FetchUsers()

				passOne, _ := usersRepo.GetPasswordCompare(email[0])
				passTwo, _ := usersRepo.GetPasswordCompare(email[1])
				passThree, _ := usersRepo.GetPasswordCompare(email[2])

				Expect(err).ToNot(HaveOccurred())

				Expect(userList[0].Email).To(Equal(email[0]))
				Expect(userList[0].Password).To(Equal(*passOne))
				Expect(userList[0].RoleID).To(Equal(1))
				Expect(userList[1].Email).To(Equal(email[1]))
				Expect(userList[1].Password).To(Equal(*passTwo))
				Expect(userList[1].RoleID).To(Equal(2))
				Expect(userList[2].Email).To(Equal(email[2]))
				Expect(userList[2].Password).To(Equal(*passThree))
				Expect(userList[2].RoleID).To(Equal(2))
			})
			It("should return user participant", func() {
				participant, err := usersRepo.FetchParticipant()
				Expect(err).ToNot(HaveOccurred())
				Expect(participant[0].Fullname).To((Equal("arin cantika")))
				Expect(participant[0].Title).To((Equal("Kelas Coding")))
				Expect(participant[0].DetailRole).To((Equal("participant")))
			})
			It("should return user volunteer", func() {
				volunteer, err := usersRepo.FetchVolunteer()
				Expect(err).ToNot(HaveOccurred())
				Expect(volunteer[0].Fullname).To((Equal("dewi sugianti")))
				Expect(volunteer[0].Title).To((Equal("Kelas Coding")))
				Expect(volunteer[0].DetailRole).To((Equal("volunteer")))
			})
		})
	})
	Describe("Login", func() {
		When("email and password are correct", func() {
			It("accepts the login", func() {
				pass, _ := usersRepo.GetPasswordCompare("admin@gmail.com")
				res, err := usersRepo.LoginUser("admin@gmail.com", *pass)

				Expect(err).ToNot(HaveOccurred())
				Expect(*res).To(Equal("admin@gmail.com"))
			})
		})
		When("email is correct but password is incorrect", func() {
			It("rejects the login", func() {
				_, err := usersRepo.LoginUser("admin@gmail.com", "123")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("login failed"))
			})
		})
		When("both username and password is incorrect", func() {
			It("rejects the login", func() {
				_, err := usersRepo.LoginUser("admin@gehol.com", "123")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("login failed"))
			})
		})
	})
	Describe("Select All Class", func() {
		When("get all class list from database", func() {
			It("should return all class list", func() {
				classList, err := classRepo.FetchClass()
				Expect(err).ToNot(HaveOccurred())
				var classTitle = []string{"Kelas Coding", "Kelas Menulis", "Kelas Melukis", "Kelas Membaca"}
				var classDate = []string{"2022-06-18T00:00:00Z", "2022-06-18T00:00:00Z", "2022-06-18T00:00:00Z", "2022-06-18T00:00:00Z"}
				var classTime = []string{"16:00:00", "16:00:00", "16:00:00", "16:00:00"}
				var classPlace = []string{"UNJ Kampus B", "UNJ Kampus B", "UNJ Kampus B", "UNJ Kampus B"}
				var classImg = []string{"coding.jpg", "menulis.jpg", "melukis.jpg", "membaca.jpg"}

				for i := 0; i < 4; i++ {
					Expect(classList[i].Title).To(Equal(classTitle[i]))
					Expect(classList[i].Date).To(Equal(classDate[i]))
					Expect(classList[i].Time).To(Equal(classTime[i]))
					Expect(classList[i].Place).To(Equal(classPlace[i]))
					Expect(classList[i].Image).To(Equal(classImg[i]))
				}
			})
		})
	})
	Describe("Add Class Schedule", func() {
		When("select class and confirm will add class to event", func() {
			It("add class to the event", func() {
				class, err := classRepo.FetchClassByID(1)
				Expect(err).ToNot(HaveOccurred())
				classRepo.ResetClass()
				classRepo.AddNewClass(class.Title, class.Date, class.Time, class.Place, class.Image, class.Detail)

				classNew, err := classRepo.FetchClass()
				Expect(err).ToNot(HaveOccurred())
				Expect(classNew[0].Title).To(Equal("Kelas Coding"))
				Expect(classNew[0].Date).To(Equal("2022-06-18T00:00:00Z"))
				Expect(classNew[0].Time).To(Equal("16:00:00"))
				Expect(classNew[0].Place).To(Equal("UNJ Kampus B"))
				Expect(classNew[0].Image).To(Equal("coding.jpg"))
			})
			It("update class to the event", func() {
				class, err := classRepo.FetchClassByID(1)
				Expect(err).ToNot(HaveOccurred())
				classTwo, err := classRepo.FetchClassByID(2)
				Expect(err).ToNot(HaveOccurred())
				classRepo.ResetClass()
				classRepo.AddNewClass(class.Title, class.Date, class.Time, class.Place, class.Image, class.Detail)

				classNew, err := classRepo.FetchClassByID(5)
				Expect(err).ToNot(HaveOccurred())
				classItem, err := classRepo.UpdateClass(classNew.ID, classTwo.Title, classTwo.Date, classTwo.Time, classTwo.Place, classTwo.Image, classTwo.Detail)
				Expect(err).ToNot(HaveOccurred())
				Expect(classItem).To(Equal(true))
			})
		})
	})
	Describe("Select All Gallery", func() {
		When("get all gallery list from database", func() {
			It("should return all gallery list", func() {
				galleryList, err := galleryRepo.FetchGallery()

				var galleryDesc = []string{"activity 1", "activity 2", "activity 3", "activity 4", "activity 5", "activity 6"}
				var galleryImg = []string{"gallery1.jpg", "gallery2.jpg", "gallery3.jpg", "gallery4.jpg", "gallery5.jpg", "gallery6.jpg"}

				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < 6; i++ {
					Expect(galleryList[i].Image).To(Equal(galleryImg[i]))
					Expect(galleryList[i].Description).To(Equal(galleryDesc[i]))
				}
			})
		})
	})
	Describe("Add Gallery Image", func() {
		When("select gallery and confirm will add image to gallery", func() {
			It("add image to the gallery", func() {
				img, err := galleryRepo.FetchGalleryByID(1)
				Expect(err).ToNot(HaveOccurred())
				galleryRepo.ResetGalleryImage()
				galleryRepo.AddNewGallery(img.Image, img.Description)

				imgNew, err := galleryRepo.FetchGallery()
				Expect(err).ToNot(HaveOccurred())
				Expect(imgNew[0].Image).To(Equal("gallery1.jpg"))
				Expect(imgNew[0].Description).To(Equal("activity 1"))
			})
			It("update image to the gallery", func() {
				img, err := galleryRepo.FetchGalleryByID(1)
				Expect(err).ToNot(HaveOccurred())
				imgTwo, err := galleryRepo.FetchGalleryByID(2)
				Expect(err).ToNot(HaveOccurred())
				galleryRepo.ResetGalleryImage()
				galleryRepo.AddNewGallery(img.Image, img.Description)

				imgNew, err := galleryRepo.FetchGalleryByID(1)
				Expect(err).ToNot(HaveOccurred())
				galleryItem, err := galleryRepo.UpdateGallery(imgNew.ID, imgTwo.Image, imgTwo.Description)
				Expect(err).ToNot(HaveOccurred())
				Expect(galleryItem).To(Equal(true))
			})
		})
	})
	Describe("Choose Role User", func() {
		When("select activities user and confirm user can choose role to activities", func() {
			It("should return activities list", func() {
				activities, err := activityRepo.FetchActivities()
				Expect(err).ToNot(HaveOccurred())

				Expect(activities[0].UserID).To(Equal(2))
				Expect(activities[0].ClassID).To(Equal(1))
				Expect(activities[0].RoleActID).To(Equal(1))
				Expect(activities[1].UserID).To(Equal(3))
				Expect(activities[1].ClassID).To(Equal(1))
				Expect(activities[1].RoleActID).To(Equal(2))
			})
			It("user choose role to activities", func() {
				act, err := activityRepo.FetchActivities()
				Expect(err).ToNot(HaveOccurred())
				activityRepo.ResetActivity()
				for i := 0; i < 2; i++ {
					activityRepo.ChooseRole(act[i].UserID, act[i].ClassID, act[i].RoleActID)
				}
				actNew, err := activityRepo.FetchActivities()
				Expect(err).ToNot(HaveOccurred())

				Expect(actNew[0].UserID).To(Equal(2))
				Expect(actNew[0].ClassID).To(Equal(1))
				Expect(actNew[0].RoleActID).To(Equal(1))
				Expect(actNew[1].UserID).To(Equal(3))
				Expect(actNew[1].ClassID).To(Equal(1))
				Expect(actNew[1].RoleActID).To(Equal(2))
			})
			It("user can check their activities", func() {
				act, err := activityRepo.FetchActivityByID(2)
				Expect(err).ToNot(HaveOccurred())

				Expect(act[0].Title).To(Equal("Kelas Coding"))
				Expect(act[0].Date).To(Equal("2022-06-18T00:00:00Z"))
				Expect(act[0].Time).To(Equal("16:00:00"))
				Expect(act[0].Place).To(Equal("UNJ Kampus B"))
				Expect(act[0].Image).To(Equal("coding.jpg"))
			})
		})
	})

})

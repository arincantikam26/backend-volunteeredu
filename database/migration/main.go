package main

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3" //third party API, import indirect
)

func main() {

	db, err := sql.Open("sqlite3", "../VolunteerEdu.db")

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
		(3, 'Kelas Melukis', '2022-06-18', '16:00:00', 'UNJ Kampus B', 'menulis.jpg', 'kelas melukis ini dapat diikuti oleh semua umur'),
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

	defer db.Close()
}

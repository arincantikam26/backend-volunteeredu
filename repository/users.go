package repository

import (
	"database/sql"
	"errors"
	"time"
)

type Repository interface {
	FetchUsers() ([]User, error)
	FetchUserByID(ID int) (User, error)
	InsertUser(full_name string, email string, date_birth string, password string, phone string, address string) (*string, error)
	LoginUser(email string, password string) (*string, error)
	FetchUserRole(email string) (*string, error)
	FetchUserIdByEmail(email string) (*int, error)
	UpdateUser(full_name string, email string, date_birth time.Time, password string, phone string, address string) (*string, error)
	PushToken(user_id int, token string, expired_at time.Time) (*string, error)
	FetchParticipant() ([]ListResponse, error)
	FetchVolunteer() ([]ListResponse, error)
	GetPasswordCompare(email string) (*string, error)
	GetUserIDByToken(token string) (*int, error)
	DeleteToken(token string) (bool, error)
}

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (u *UserRepository) FetchUserByID(id int) (User, error) {
	user := User{}
	sqlStatement := `SELECT * FROM users WHERE user_id = ?`

	row := u.db.QueryRow(sqlStatement, id)
	err := row.Scan(
		&user.ID,
		&user.Fullname,
		&user.Email,
		&user.DateBirth,
		&user.Password,
		&user.Phone,
		&user.Address,
		&user.RoleID,
	)
	if err != nil {
		return user, err
	}
	return user, nil
	// defer row.Close()
}

func (u *UserRepository) FetchUsers() ([]User, error) {
	var users []User

	rows, err := u.db.Query("SELECT * FROM users")
	if err != nil {
		return users, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User

		err := rows.Scan(
			&user.ID,
			&user.Fullname,
			&user.Email,
			&user.DateBirth,
			&user.Password,
			&user.Phone,
			&user.Address,
			&user.RoleID,
		)
		if err != nil {
			return users, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (u *UserRepository) InsertUser(full_name string, email string, date_birth string, password string, phone string, address string) (*string, error) {
	users, err := u.FetchUsers()

	for _, value := range users {
		if value.Email == email {
			return nil, err
		}
	}
	_, err = u.db.Exec("INSERT INTO users (full_name, email, date_birth, password, phone, address) VALUES (?,?,?,?,?,?)", full_name, email, date_birth, password, phone, address)

	if err != nil {
		return nil, err
	}

	return &email, err
}

func (u *UserRepository) UpdateUser(id int, full_name string, email string, date_birth time.Time, password string, phone string, address string) (*string, error) {
	_, err := u.db.Exec("UPDATE users SET full_name = ?, email = ?, date_birth = ?, password = ?, phone = ?, address = ? WHERE user_id = ?)",
		full_name, email, date_birth, password, phone, address, id)

	if err != nil {
		return nil, err
	}

	return &email, err

}

func (u *UserRepository) FetchUserRole(email string) (*string, error) {
	var role string

	rows, err := u.db.Query("SELECT role_user_id FROM users WHERE email = ?", email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&role)
		if err != nil {
			return nil, err
		}
	}
	return &role, nil
}

func (u *UserRepository) FetchUserIdByEmail(email string) (*int, error) {
	var user_id int

	rows, err := u.db.Query("SELECT user_id FROM users WHERE email = ?", email)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&user_id)
		if err != nil {
			return nil, err
		}
	}
	return &user_id, nil
}

func (u *UserRepository) LoginUser(email string, password string) (*string, error) {
	users, err := u.FetchUsers()
	if err != nil {
		return nil, errors.New("login failed")
	}

	for _, user := range users {

		if user.Email == email && user.Password == password {
			return &email, nil
		}

	}
	return nil, errors.New("login failed")
}

func (u *UserRepository) FetchParticipant() ([]ListResponse, error) {

	var lists []ListResponse

	sqlStatement := `SELECT activity_id, u.full_name, cs.title, ra.detail FROM activities a 
						INNER JOIN users u ON a.user_id = u.user_id 
						INNER JOIN class_schedules cs ON a.class_id = cs.class_id 
						INNER JOIN role_act ra ON a.role_act_id = ra.role_act_id
					WHERE ra.detail = 'participant';
					`
	rows, err := u.db.Query(sqlStatement)
	if err != nil {
		return lists, err
	}

	for rows.Next() {
		var list ListResponse

		err := rows.Scan(
			&list.ID,
			&list.Fullname,
			&list.Title,
			&list.DetailRole,
		)
		if err != nil {
			return lists, err
		}
		lists = append(lists, list)
	}
	return lists, nil
}

func (u *UserRepository) FetchVolunteer() ([]ListResponse, error) {

	var lists []ListResponse

	sqlStatement := `SELECT activity_id, u.full_name, cs.title, ra.detail FROM activities a 
						INNER JOIN users u ON a.user_id = u.user_id 
						INNER JOIN class_schedules cs ON a.class_id = cs.class_id 
						INNER JOIN role_act ra ON a.role_act_id = ra.role_act_id
					WHERE ra.detail = 'volunteer';
					`
	rows, err := u.db.Query(sqlStatement)
	if err != nil {
		return lists, err
	}

	for rows.Next() {
		var list ListResponse

		err := rows.Scan(
			&list.ID,
			&list.Fullname,
			&list.Title,
			&list.DetailRole,
		)
		if err != nil {
			return lists, err
		}
		lists = append(lists, list)
	}
	return lists, nil
}

func (u *UserRepository) PushToken(user_id int, token string, expired_at time.Time) (*string, error) {
	_, err := u.db.Exec("INSERT INTO auth (user_id, token, expired_at) VALUES (?, ?,?)",
		user_id, token, expired_at)

	if err != nil {
		return nil, err
	}
	return &token, err
}

func (u *UserRepository) DeleteToken(token string) (bool, error) {
	_, err := u.db.Exec("DELETE FROM auth WHERE token = ?", token)

	if err != nil {
		return false, err
	}
	return true, err
}

func (u *UserRepository) GetUserIDByToken(token string) (*int, error) {
	var user_id int

	sqlStatement := `SELECT user_id FROM auth WHERE token = ?`

	row := u.db.QueryRow(sqlStatement, token)
	err := row.Scan(&user_id)
	if err != nil {
		return nil, err
	}
	return &user_id, nil

}

func (u *UserRepository) GetPasswordCompare(email string) (*string, error) {
	var pass string
	sqlStatement := `SELECT password FROM users WHERE email = ?`

	row := u.db.QueryRow(sqlStatement, email)
	err := row.Scan(&pass)
	if err != nil {
		return nil, err
	}
	return &pass, err
}

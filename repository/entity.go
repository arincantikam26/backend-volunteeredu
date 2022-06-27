package repository

type User struct {
	ID        int    `json:"user_id"`
	Fullname  string `json:"full_name"`
	Email     string `json:"email"`
	DateBirth string `json:"date_birth"`
	Password  string `json:"password"`
	Phone     string `json:"phone"`
	Address   string `json:"address"`
	RoleID    int    `json:"role_user_id"`
}

type Class struct {
	ID     int    `json:"class_id"`
	Title  string `json:"title"`
	Date   string `json:"date"`
	Time   string `json:"time"`
	Place  string `json:"place"`
	Image  string `json:"image"`
	Detail string `json:"detail"`
}

type Activities struct {
	ID        int `json:"activity_id"`
	UserID    int `json:"user_id"`
	ClassID   int `json:"class_id"`
	RoleActID int `json:"role_act_id"` //participan or volunteer
}

type Role struct {
	ID     int    `json:"role_act_id"`
	Detail string `json:"detail"`
}

type RoleUser struct {
	ID     int    `json:"role_user_id"`
	Detail string `json:"detail"`
}

type Gallery struct {
	ID          int    `json:"gallery_id"`
	Image       string `json:"image"`
	Description string `json:"description"`
}

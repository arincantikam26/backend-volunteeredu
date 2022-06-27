package repository

type UserRequest struct {
	Fullname  string `json:"full_name" binding:"required"`
	Email     string `json:"email" binding:"required"`
	DateBirth string `json:"date_birth" binding:"required"`
	Password  string `json:"password" binding:"required"`
	Phone     string `json:"phone" binding:"required"`
	Address   string `json:"address" binding:"required"`
}

type ClassRequest struct {
	Title  string `json:"title"`
	Date   string `json:"date"`
	Time   string `json:"time"`
	Place  string `json:"place"`
	Image  string `json:"image"`
	Detail string `json:"detail"`
}

type ListResponse struct {
	ID         int    `json:"activity_id"`
	Fullname   string `json:"full_name"`
	DetailRole string `json:"detail"`
	Title      string `json:"title"`
}

type MyActivity struct {
	ID         int    `json:"activity_id"`
	Title      string `json:"title"`
	Date       string `json:"date"`
	Time       string `json:"time"`
	Place      string `json:"place"`
	Image      string `json:"image"`
	DetailRole string `json:"detail"`
}

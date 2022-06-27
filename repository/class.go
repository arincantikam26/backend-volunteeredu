package repository

import (
	"database/sql"
)

type ClassRepo interface {
	FetchClass() ([]Class, error)
	FetchClassByID(ID int) (Class, error)
	FetchClassLimit() ([]Class, error)
	AddNewClass(title string, date string, time string, place string, image string, detail string) (*string, error)
	UpdateClass(class Class) (bool, error)
	DeleteClass(id int) (bool, error)
	FetchNameImgClassId(id int) (*string, error)
}

type ClassRepository struct {
	db *sql.DB
}

func NewClassRepository(db *sql.DB) *ClassRepository {
	return &ClassRepository{db: db}
}

func (c *ClassRepository) FetchClass() ([]Class, error) {
	var classes []Class

	rows, err := c.db.Query("SELECT * FROM class_schedules")
	if err != nil {
		return classes, err
	}

	for rows.Next() {
		var class Class

		err := rows.Scan(
			&class.ID,
			&class.Title,
			&class.Date,
			&class.Time,
			&class.Place,
			&class.Image,
			&class.Detail,
		)
		if err != nil {
			return classes, err
		}
		classes = append(classes, class)
	}
	return classes, nil
}

func (c *ClassRepository) FetchClassByID(ID int) (Class, error) {
	class := Class{}
	sqlStatement := `SELECT * FROM class_schedules WHERE class_id = ?`

	row := c.db.QueryRow(sqlStatement, ID)
	err := row.Scan(
		&class.ID,
		&class.Title,
		&class.Date,
		&class.Time,
		&class.Place,
		&class.Image,
		&class.Detail,
	)
	if err != nil {
		return class, err
	}
	return class, nil
}

func (c *ClassRepository) FetchClassLimit() ([]Class, error) {
	var classes []Class

	rows, err := c.db.Query("SELECT * FROM class_schedules LIMIT 3")
	if err != nil {
		return classes, err
	}

	for rows.Next() {
		var class Class

		err := rows.Scan(
			&class.ID,
			&class.Title,
			&class.Date,
			&class.Time,
			&class.Place,
			&class.Image,
			&class.Detail,
		)
		if err != nil {
			return classes, err
		}
		classes = append(classes, class)
	}
	return classes, nil
}

func (c *ClassRepository) AddNewClass(title string, date string, time string, place string, image string, detail string) (*string, error) {

	sqlStatement := `INSERT INTO class_schedules (title, date, time, place, image, detail) VALUES (?, ?, ?, ?, ?, ?)`

	_, err := c.db.Exec(sqlStatement, title, date, time, place, image, detail)
	if err != nil {
		return nil, err
	}
	return &title, nil
}

func (c *ClassRepository) UpdateClass(id int, title string, date string, time string, place string, image string, detail string) (bool, error) {
	sqlStatement := `UPDATE class_schedules SET title = ?, date = ?, time = ?, place = ?, image = ?, detail = ? WHERE class_id = ?`

	_, err := c.db.Exec(sqlStatement, title, date, time, place, image, detail, id)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *ClassRepository) DeleteClass(id int) (bool, error) {
	sqlStatement := `DELETE from class_schedules WHERE class_id = ?`

	_, err := c.db.Exec(sqlStatement, id)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *ClassRepository) FetchNameImgClassId(id int) (*string, error) {
	class := Class{}
	sqlStatement := `SELECT image FROM class_schedules WHERE class_id = ?`

	row := c.db.QueryRow(sqlStatement, id)
	err := row.Scan(
		&class.Image,
	)
	if err != nil {
		return nil, err
	}
	return &class.Image, nil
}

func (g *ClassRepository) ResetClass() error {
	sqlStatement := `DELETE FROM class_schedules`
	_, err := g.db.Exec(sqlStatement)
	if err != nil {
		return err
	}
	return nil
}

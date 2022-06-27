package repository

import (
	"database/sql"
)

type GalleryRepo interface {
	FetchGallery() ([]Gallery, error)
	FetchGalleryByID(id int) (Gallery, error)
	AddNewGallery(image string, description string) (*string, error)
	UpdateGallery(id int, image string, description string) (bool, error)
	DeleteGallery(id int) (bool, error)
	FetchGalleryLimit() ([]Gallery, error)
	FetchNameImageById(id int) (Gallery, error)
	ResetGalleryImage() error
}

type GalleryRepository struct {
	db *sql.DB
}

func NewGalleryRepo(db *sql.DB) *GalleryRepository {
	return &GalleryRepository{db: db}
}

func (g *GalleryRepository) FetchGallery() ([]Gallery, error) {
	var galeries []Gallery

	rows, err := g.db.Query("SELECT * FROM gallery")
	if err != nil {
		return galeries, err
	}

	for rows.Next() {
		var gallery Gallery

		err := rows.Scan(
			&gallery.ID,
			&gallery.Image,
			&gallery.Description,
		)
		if err != nil {
			return galeries, err
		}
		galeries = append(galeries, gallery)
	}
	return galeries, nil
}

func (g *GalleryRepository) FetchGalleryByID(id int) (Gallery, error) {
	gallery := Gallery{}
	sqlStatement := `SELECT * FROM gallery WHERE gallery_id = ?`

	row := g.db.QueryRow(sqlStatement, id)
	err := row.Scan(
		&gallery.ID,
		&gallery.Image,
		&gallery.Description,
	)
	if err != nil {
		return gallery, nil
	}
	return gallery, nil
}

func (g *GalleryRepository) AddNewGallery(image string, description string) (*string, error) {
	sqlStatement := `INSERT INTO gallery (image, description) VALUES (?,?)`

	_, err := g.db.Exec(sqlStatement, image, description)
	if err != nil {
		return nil, err
	}
	return &image, nil
}

func (g *GalleryRepository) UpdateGallery(id int, image string, description string) (bool, error) {
	sqlStatement := `UPDATE gallery SET image = ?, description = ? WHERE gallery_id = ?`
	_, err := g.db.Exec(sqlStatement, image, description, id)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (g *GalleryRepository) DeleteGallery(id int) (bool, error) {
	sqlStatement := `DELETE FROM gallery WHERE gallery_id = ?`

	_, err := g.db.Exec(sqlStatement, id)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (g *GalleryRepository) FetchGalleryLimit() ([]Gallery, error) {
	var galeries []Gallery

	rows, err := g.db.Query("SELECT * FROM gallery LIMIT 6")
	if err != nil {
		return galeries, err
	}

	for rows.Next() {
		var gallery Gallery

		err := rows.Scan(
			&gallery.ID,
			&gallery.Image,
			&gallery.Description,
		)
		if err != nil {
			return galeries, err
		}
		galeries = append(galeries, gallery)
	}
	return galeries, nil
}

func (g *GalleryRepository) FetchNameImageById(id int) (*string, error) {
	gallery := Gallery{}
	sqlStatement := `SELECT image FROM gallery WHERE gallery_id = ?`

	row := g.db.QueryRow(sqlStatement, id)
	err := row.Scan(
		&gallery.Image,
	)
	if err != nil {
		return nil, err
	}
	return &gallery.Image, nil
}

func (g *GalleryRepository) ResetGalleryImage() error {
	sqlStatement := `DELETE FROM gallery`
	_, err := g.db.Exec(sqlStatement)
	if err != nil {
		return err
	}
	return nil
}

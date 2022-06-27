package repository

import (
	"database/sql"
)

type RoleRepository struct {
	db *sql.DB
}

func NewRoleRepository(db *sql.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

func (r *RoleRepository) GetRole() ([]Role, error) {
	var roles []Role
	rows, err := r.db.Query("SELECT * FROM role_act")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var role Role
		err := rows.Scan(
			&role.ID,
			&role.Detail,
		)
		if err != nil {
			return roles, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

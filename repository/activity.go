package repository

import (
	"database/sql"
)

type ActivityRepository struct {
	db *sql.DB
}

type ActivityInterface interface {
	ChooseRole(user_id int, class_id int, role_act string) ([]Activities, error)
	FetchActivityByID(id int) ([]MyActivity, error)
	ResetActivity() error
}

func NewActivityRepository(db *sql.DB) *ActivityRepository {
	return &ActivityRepository{db: db}
}
func (a *ActivityRepository) FetchActivities() ([]Activities, error) {
	var activities []Activities

	rows, err := a.db.Query("SELECT * FROM activities")

	if err != nil {
		return activities, err
	}
	defer rows.Close()

	for rows.Next() {
		var activity Activities

		err := rows.Scan(
			&activity.ID,
			&activity.UserID,
			&activity.ClassID,
			&activity.RoleActID,
		)
		if err != nil {
			return activities, err
		}
		activities = append(activities, activity)
	}
	return activities, nil
}

func (a *ActivityRepository) ChooseRole(userID int, classID int, role_act_id int) (*int, error) {
	activities, err := a.FetchActivities()

	for _, res := range activities {
		if res.UserID == userID && res.ClassID == classID {
			return nil, err
		}
	}
	sqlStatement := `INSERT INTO activities (user_id, class_id, role_act_id)
	VALUES (?,?,?)`

	_, err = a.db.Exec(sqlStatement, userID, classID, role_act_id)
	if err != nil {
		return nil, err
	}
	return &role_act_id, nil
}

func (a *ActivityRepository) FetchActivityByID(id int) ([]MyActivity, error) {
	var myActivity []MyActivity
	sqlStatement := `
		SELECT 
			a.activity_id,
			c.title,
			c.date,
			c.time,
			c.place,
			c.image,
			r.detail
		FROM activities a
			INNER JOIN class_schedules c ON a.class_id = c.class_id
			INNER JOIN role_act r ON a.role_act_id = r.role_act_id
		Where user_id = ?`

	row, err := a.db.Query(sqlStatement, id)
	if err != nil {
		return nil, err
	}
	defer row.Close()
	for row.Next() {
		var myAct MyActivity
		err := row.Scan(
			&myAct.ID,
			&myAct.Title,
			&myAct.Date,
			&myAct.Time,
			&myAct.Place,
			&myAct.Image,
			&myAct.DetailRole,
		)
		if err != nil {
			return nil, err
		}
		myActivity = append(myActivity, myAct)
	}
	return myActivity, nil

}

func (a *ActivityRepository) ResetActivity() error {
	sqlStatement := `DELETE FROM activities`
	_, err := a.db.Exec(sqlStatement)
	if err != nil {
		return err
	}
	return nil
}

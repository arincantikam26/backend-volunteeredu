![Image alt text](logoVE.png)

# Final Project Kelompok 74 - VolunteerEdu

## Profile Team
|ID | Nama | Role | Profile |
| ------ | ------ | ------ | ------ |
| BE2122257 | Arin Cantika Musi | Backend Engineer | [arincantikam26](https://github.com/arincantikam26) |
| BE2244403 | Dewi Sugianti | Backend Engineer | [dewsgnt](https://github.com/dewsgnt) |
| FE2311163 | Muhammad Rafi Akbar | Frontend Engineer | [rafiakbar13](https://github.com/rafiakbar13) |
| FE2306138 | Sechan Al Farisi | Frontend Engineer | [alfarisisechan](https://github.com/alfarisisechan) |
| FE2239831 | Ni Luh Dita Oktaviari | Frontend Engineer | [ditaoktaviari](https://github.com/ditaoktaviari) |
| FE2001900 | Dzihan Septiangraini | Frontend Engineer | [DzihanSeptiangraini](https://github.com/DzihanSeptiangraini) |

## Requirements

- There are two users, admin and volunteer/participant.
- User should able to signup to the system.
- User should able to login to the system.
- User should able to logout from the system.
- User should able to choose role in class.
- User should able to check gallery activities.
- User should able to check list activities class.
- Admin should able to get list user.
- Admin should able to manage class schedules.
- Admin should able to manage gallery.

## How to run service
Run the following code in terminal:
1. Migration: run `main.go` inside directory `final-project-engineering-74\backend\database\migration` to Migration database SQLite
```
cd backend/database/migration
go run main.go
```

2. Main Service: run `main.go` inside directory `final-project-engineering-74\backend` to running main service
```
cd backend/
go run main.go
```

3. Main Page: run `npm start` inside directory `final-project-engineering-74\frontend` ro running main page
```
cd frontend/
npm start
``` 
nb : you must run inside the root directory `final-project-engineering-74`

# BACKEND
## Available APIs
### User
#### Register user
- Method : `POST`
- Endpoint : `/api/v1/users/regist`
#### Login user
- Method : `POST`
- Endpoint : `/api/v1/users/login`
#### Logout user
- Method : `POST`
- Endpoint : `/api/v1/users/logout`
#### Get all user
- Method : `GET`
- Endpoint : `/api/v1/users`
#### Get user by id
- Method : `GET`
- Endpoint : `/api/v1/users/:id`
#### Get user by token
- Method : `GET`
- Endpoint : `/api/v1/users/token/:id`
------
### Class Schedule
#### Get all class
- Method : `GET`
- Endpoint : `/api/v1/classes`
#### Get class by id
- Method : `GET`
- Endpoint : `/api/v1/classes/:id`
#### Get class limit
- Method : `GET`
- Endpoint : `/api/v1/class/limit`
#### Admin add class
- Method : `POST`
- Endpoint : `/api/v1/add/class`
#### Admin update class
- Method : `PATCH`
- Endpoint : `/api/v1/class/update/:id`
#### Admin delete class
- Method : `POST`
- Endpoint : `/api/v1/class/delete/:id`
------
### Gallery
#### Get all gallery
- Method : `GET`
- Endpoint : `/api/v1/gallery`
#### Get gallery by id
- Method : `GET`
- Endpoint : `/api/v1/gallery/:id`
#### Get gallery limit
- Method : `GET`
- Endpoint : `/api/v1/gallery/limit`
#### Admin add gallery
- Method : `POST`
- Endpoint : `/api/v1/gallery/add`
#### Admin update gallery
- Method : `PATCH`
- Endpoint : `/api/v1/gallery/update/:id`
#### Admin delete gallery
- Method : `POST`
- Endpoint : `/api/v1/gallery/delete/:id`
------
### Activities
#### Get user activity
- Method : `GET`
- Endpoint : `/api/v1/myactivity/:id`
#### Get roles user
- Method : `GET`
- Endpoint : `/api/v1/roles`
#### Choose roles user
- Method : `POST`
- Endpoint : `/api/v1/chooserole`
------
### Admin
#### Get list participant
- Method : `GET`
- Endpoint : `/api/v1/participate`
#### Get list volunteer
- Method : `GET`
- Endpoint : `/api/v1/volunteer`
------
## Unit-testing
Run the following code in terminal:
1. Repository-test: run `main.go` inside directory `final-project-engineering-74\backend\repository` to running unit-test using ginkgo
```
cd backend/repository
ginkgo . or ginkgo -v
```

# FRONTEND
# API Documentation

### Register

Method: POST
Data Request: 
{
  "nama": "...",
  "email": "...",
  "password": "..."
}

Data Response:
- Berhasil
  {
    message: "success"
  }

- Gagal
  {
    message: "fail"
  }
  
  
### Login

Method: POST
Data Request: 
{
  "email": "...",
  "password": "..."
}

Data Response:
- Berhasil
  {
    message: "success"
  }

- Gagal
  {
    message: "fail"
  }

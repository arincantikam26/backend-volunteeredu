package api

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/arincantikam26/volunteeredu/repository"
	"github.com/gin-gonic/gin"
)

type ClassResponse struct {
	ID     int    `json:"class_id"`
	Title  string `json:"title"`
	Date   string `json:"date"`
	Time   string `json:"time"`
	Place  string `json:"place"`
	Image  string `json:"image"`
	Detail string `json:"detail"`
}

type ClassForm struct {
	Title  string `form:"title"`
	Date   string `form:"date"`
	Time   string `form:"time"`
	Place  string `form:"place"`
	Image  string `json:"image"`
	Detail string `form:"detail"`
}

func (api *API) GetClasses(c *gin.Context) {
	classes, err := api.classRepo.FetchClass()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}

	var classesResponse []ClassResponse

	for _, class := range classes {
		classResponse := convertToClassResponse(class)

		classesResponse = append(classesResponse, classResponse)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": classesResponse,
	})
}

func (api *API) GetClassLimit(c *gin.Context) {
	classes, err := api.classRepo.FetchClassLimit()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}

	var classesResponse []ClassResponse

	for _, class := range classes {
		classResponse := convertToClassResponse(class)

		classesResponse = append(classesResponse, classResponse)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": classesResponse,
	})
}

func (api *API) GetClassByID(c *gin.Context) {
	ID := c.Param("id")
	classid, _ := strconv.Atoi(ID)

	res, err := api.classRepo.FetchClassByID(classid)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": res,
	})
}

func (api *API) AddNewClass(c *gin.Context) {
	var class ClassForm
	if err := c.ShouldBind(&class); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}

	class.Image = UploadFileClass(c)
	dateParse, _ := time.Parse("2006-01-02", class.Date)

	class.Date = dateParse.Format("2006-01-02")

	if class.Image == "" {
		c.JSON(http.StatusBadRequest, "error: Input is empty")
		return
	}

	_, err := api.classRepo.AddNewClass(class.Title, class.Date, class.Time, class.Place, class.Image, class.Detail)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  http.StatusOK,
		"message": "Add class success",
	})
}

func (api *API) UpdateClass(c *gin.Context) {
	var class ClassForm

	if err := c.ShouldBind(&class); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}
	classId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
	}

	oldImg, err := api.classRepo.FetchNameImgClassId(classId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	class.Image = UploadFileClass(c)

	if class.Image != "" {
		if err := api.DeleteFileClass(c, classId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		class.Image = *oldImg
	}

	success, err := api.classRepo.UpdateClass(classId, class.Title, class.Date, class.Time, class.Place, class.Image, class.Detail)
	if success {
		c.JSON(http.StatusOK, gin.H{"message": "Update Success"})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
	}
}

func (api *API) DeleteClass(c *gin.Context) {
	classId, err := strconv.Atoi(c.Param("id"))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
	}

	if err := api.DeleteFileClass(c, classId); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	success, err := api.classRepo.DeleteClass(classId)
	if success {
		c.JSON(http.StatusOK, gin.H{"message": "Class Delete Success"})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
	}

}

func UploadFileClass(c *gin.Context) (fileName string) {
	c.Request.ParseMultipartForm(10 << 20)

	file, err := c.FormFile("image")

	if file != nil && err == nil {
		src, err := file.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		defer src.Close()

		filepath := "../frontend/src/assets/" + file.Filename

		dst, err := os.Create(filepath)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			panic(err)
		}
		defer dst.Close()

		if _, err := io.Copy(dst, src); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			panic(err)
		}
		return file.Filename
	}
	return ""
}

func (api *API) DeleteFileClass(c *gin.Context, id int) error {
	oldFile, err := api.classRepo.FetchNameImgClassId(id)

	filepath := "../frontend/src/assets/" + *oldFile

	if *oldFile != "" {
		if err := os.Remove(filepath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			panic(err)
		}
		return err
	}
	return nil
}

func convertToClassResponse(h repository.Class) ClassResponse {
	return ClassResponse{
		ID:     h.ID,
		Title:  h.Title,
		Date:   h.Date,
		Time:   h.Time,
		Place:  h.Place,
		Image:  h.Image,
		Detail: h.Detail,
	}
}

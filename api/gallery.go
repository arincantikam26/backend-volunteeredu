package api

import (
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/arincantikam26/volunteeredu/repository"
	"github.com/gin-gonic/gin"
)

type GalleryUpload struct {
	Image       string `json:"image"`
	Description string `form:"description"`
}

func (api *API) GetGallery(c *gin.Context) {
	//api.AllowOrigin(c)
	galeries, err := api.galleryRepo.FetchGallery()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}

	var galleryResponse []repository.Gallery

	for _, value := range galeries {
		gallery := convertToGalleryResponse(value)
		galleryResponse = append(galleryResponse, gallery)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": galleryResponse,
	})

}

func (api *API) GetGalleryLimit(c *gin.Context) {
	// //api.AllowOrigin(c)
	galeries, err := api.galleryRepo.FetchGalleryLimit()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}

	var galleryResponse []repository.Gallery

	for _, value := range galeries {
		gallery := convertToGalleryResponse(value)
		galleryResponse = append(galleryResponse, gallery)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": galleryResponse,
	})

}

func (api *API) GetGalleryByID(c *gin.Context) {
	////api.AllowOrigin(c)
	idString := c.Param("id")
	id, _ := strconv.Atoi(idString)

	result, err := api.galleryRepo.FetchGalleryByID(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": result,
	})
}

func (api *API) AddNewGallery(c *gin.Context) {
	////api.AllowOrigin(c)
	var gallery GalleryUpload

	if err := c.ShouldBind(&gallery); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}

	gallery.Image = UploadFileGallery(c)

	if gallery.Image == "" && gallery.Description == "" {
		c.JSON(http.StatusBadRequest, "error: Input is empty")
		return
	}

	_, err := api.galleryRepo.AddNewGallery(gallery.Image, gallery.Description)
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

func (api *API) UpdateGallery(c *gin.Context) {
	////api.AllowOrigin(c)

	var gallery GalleryUpload

	if err := c.ShouldBind(&gallery); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}

	galleryId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
	}

	oldGallery, err := api.galleryRepo.FetchNameImageById(galleryId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	gallery.Image = UploadFileGallery(c)

	if gallery.Image != "" {

		if err := api.DeleteFileGallery(c, galleryId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
		gallery.Image = *oldGallery

	}

	success, err := api.galleryRepo.UpdateGallery(galleryId, gallery.Image, gallery.Description)
	if success {
		c.JSON(http.StatusOK, gin.H{"message": "Update Success"})
		return
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

}

func (api *API) DeleteGallery(c *gin.Context) {
	//api.AllowOrigin(c)
	galleryId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
	}

	if err := api.DeleteFileGallery(c, galleryId); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	success, err := api.galleryRepo.DeleteGallery(galleryId)
	if success {
		c.JSON(http.StatusOK, gin.H{"message": "Class delete successfull"})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
	}
}

func UploadFileGallery(c *gin.Context) (fileName string) {
	c.Request.ParseMultipartForm(10 << 20)

	file, err := c.FormFile("image")

	if file != nil && err == nil {
		src, err := file.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		defer src.Close()

		filepath := "../frontend/src/assets/gallery/" + file.Filename

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

func (api *API) DeleteFileGallery(c *gin.Context, id int) error {
	oldFile, err := api.galleryRepo.FetchNameImageById(id)

	filepath := "../frontend/src/assets/gallery/" + *oldFile

	if *oldFile != "" {
		if err := os.Remove(filepath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			panic(err)
		}
		return err
	}
	return nil
}

func convertToGalleryResponse(api repository.Gallery) repository.Gallery {
	return repository.Gallery{
		ID:          api.ID,
		Image:       api.Image,
		Description: api.Description,
	}
}

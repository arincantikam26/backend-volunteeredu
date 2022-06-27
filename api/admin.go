package api

import (
	"net/http"

	"github.com/arincantikam26/volunteeredu/repository"
	"github.com/gin-gonic/gin"
)

type AdminErrorResponse struct {
	Error string `json:"error"`
}

type AdminResponse struct {
	ListUser []repository.ListResponse
}

func (api *API) GetListParticipate(c *gin.Context) {
	//api.AllowOrigin(c)
	users, err := api.usersRepo.FetchParticipant()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}
	var listResponse []repository.ListResponse

	for _, value := range users {
		list := convertToListResponse(value)
		listResponse = append(listResponse, list)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": listResponse,
	})
}

func (api *API) GetListVolunteer(c *gin.Context) {
	//api.AllowOrigin(c)
	users, err := api.usersRepo.FetchVolunteer()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": err,
		})
		return
	}
	var listResponse []repository.ListResponse

	for _, value := range users {
		list := convertToListResponse(value)
		listResponse = append(listResponse, list)
	}
	c.JSON(http.StatusOK, gin.H{
		"data": listResponse,
	})
}

func convertToListResponse(api repository.ListResponse) repository.ListResponse {
	return repository.ListResponse{
		ID:         api.ID,
		Fullname:   api.Fullname,
		Title:      api.Title,
		DetailRole: api.DetailRole,
	}
}

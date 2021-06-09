package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/jeremmfr/go-iptables/iptables"
	"iptables-api/forms"
	"iptables-api/models"
	"net/http"
	"strings"
)

// AddChain PUT /chain/{table}/{name}/
func AddChain(c *gin.Context) {
	ok, err := checkRole(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, forms.BasicResponse{
			Ok:      false,
			Message: "",
		})
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	err = ipt.NewChain(c.Param("table"), c.Param("name"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, forms.BasicResponse{
		Ok:      true,
		Message: "",
	})
}

// DelChain DELETE /chain/{table}/{name}/
func DelChain(c *gin.Context) {
	ok, err := checkRole(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, forms.BasicResponse{
			Ok:      false,
			Message: "",
		})
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	// Clear chain before delete
	err = ipt.ClearChain(c.Param("table"), c.Param("name"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	// Delete chain
	err = ipt.DeleteChain(c.Param("table"), c.Param("name"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, forms.BasicResponse{
		Ok:      true,
		Message: "",
	})
}

// ListChain GET /chain/{table}/{name}/
func ListChain(c *gin.Context) {
	ok, err := checkRole(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.ChainListResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, forms.ChainListResponse{
			Ok:      false,
			Message: "",
		})
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.ChainListResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	respStr, err := ipt.List(c.Param("table"), c.Param("name"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.ChainListResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}

	chains := stringToChains(respStr)

	c.JSON(http.StatusOK, forms.ChainListResponse{
		Ok:      true,
		Message: "",
		Chains:  chains,
	})
}

func stringToChains(respStr []string) []models.Chain {
	var chains []models.Chain
	for _, str := range respStr {
		splitted := strings.Split(str, " ")
		if len(splitted) > 3 && splitted[2] == "-p" {
			rule := models.Chain{
				Match:           splitted[3],
				Protocol:        splitted[5],
				DestinationPort: splitted[7],
				Destination:     splitted[11],
			}
			chains = append(chains, rule)
		}
	}

	return chains
}

// RenameChain PUT /mvchain/{table}/{oldname}/{newname}/
func RenameChain(c *gin.Context) {
	ok, err := checkRole(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, forms.BasicResponse{
			Ok:      false,
			Message: "",
		})
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	err = ipt.RenameChain(c.Param("table"), c.Param("oldname"), c.Param("newname"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, forms.BasicResponse{
		Ok:      true,
		Message: "",
	})
}

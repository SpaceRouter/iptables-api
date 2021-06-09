package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/jeremmfr/go-iptables/iptables"
	"iptables-api/forms"
	"net/http"
)

// AddChainV6 PUT /chain_v6/{table}/{name}/
func AddChainV6(c *gin.Context) {
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

	ipt, err := iptables.NewWithProtocol(v6)
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

// DelChainV6 DELETE /chain_v6/{table}/{name}/
func DelChainV6(c *gin.Context) {
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

	ipt, err := iptables.NewWithProtocol(v6)
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

// ListChainV6 GET /chain_v6/{table}/{name}/
func ListChainV6(c *gin.Context) {
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

	ipt, err := iptables.NewWithProtocol(v6)
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

// RenameChainV6 PUT /mvchain_v6/{table}/{oldname}/{newname}/
func RenameChainV6(c *gin.Context) {
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
	ipt, err := iptables.NewWithProtocol(v6)
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

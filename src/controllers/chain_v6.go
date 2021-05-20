package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jeremmfr/go-iptables/iptables"
	"net/http"
)

// AddChainV6 PUT /chain_v6/{table}/{name}/
func AddChainV6(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	respErr = ipt.NewChain(c.Param("table"), c.Param("name"))
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// DelChainV6 DELETE /chain_v6/{table}/{name}/
func DelChainV6(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Clear chain before delete
	respErr = ipt.ClearChain(c.Param("table"), c.Param("name"))
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
	// Delete chain
	respErr = ipt.DeleteChain(c.Param("table"), c.Param("name"))
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// ListChainV6 GET /chain_v6/{table}/{name}/
func ListChainV6(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	respStr, respErr := ipt.List(c.Param("table"), c.Param("name"))
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
	for i := 0; i < len(respStr); i++ {
		fmt.Fprintln(w, respStr[i])
	}
}

// RenameChainV6 PUT /mvchain_v6/{table}/{oldname}/{newname}/
func RenameChainV6(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	respErr = ipt.RenameChain(c.Param("table"), c.Param("oldname"), c.Param("newname"))
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

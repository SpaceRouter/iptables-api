package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	"github.com/jeremmfr/go-iptables/iptables"
	"github.com/spacerouter/sr_auth"
	"net/http"
)

// AddChainV6 PUT /chain_v6/{table}/{name}/
func AddChainV6(c *gin.Context) {
	w := c.Writer
	r := c.Request

	user, err := sr_auth.ExtractUser(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	roles, err := user.GetRoles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !sr_auth.HasRole(roles, iptablesRole) {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	respErr = ipt.NewChain(vars["table"], vars["name"])
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// DelChainV6 DELETE /chain_v6/{table}/{name}/
func DelChainV6(c *gin.Context) {
	w := c.Writer
	r := c.Request

	user, err := sr_auth.ExtractUser(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	roles, err := user.GetRoles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !sr_auth.HasRole(roles, iptablesRole) {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Clear chain before delete
	respErr = ipt.ClearChain(vars["table"], vars["name"])
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
	// Delete chain
	respErr = ipt.DeleteChain(vars["table"], vars["name"])
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// ListChainV6 GET /chain_v6/{table}/{name}/
func ListChainV6(c *gin.Context) {
	w := c.Writer
	r := c.Request

	user, err := sr_auth.ExtractUser(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	roles, err := user.GetRoles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !sr_auth.HasRole(roles, iptablesRole) {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	respStr, respErr := ipt.List(vars["table"], vars["name"])
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
	r := c.Request

	user, err := sr_auth.ExtractUser(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	roles, err := user.GetRoles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !sr_auth.HasRole(roles, iptablesRole) {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	respErr = ipt.RenameChain(vars["table"], vars["oldname"], vars["newname"])
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}
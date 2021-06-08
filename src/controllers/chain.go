package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jeremmfr/go-iptables/iptables"
	"net/http"
	"strings"
)

// AddChain PUT /chain/{table}/{name}/
func AddChain(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.New()
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

// DelChain DELETE /chain/{table}/{name}/
func DelChain(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.New()
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

type Rule struct {
	Mproto string
	Pproto string
	Dport string
	Dest string
}

// ListChain GET /chain/{table}/{name}/
func ListChain(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	respStr, respErr := ipt.List(c.Param("table"), c.Param("name"))
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}

	rules := stringToRules(respStr)
	data := map[string]interface{}{"Ok": true, "Rules": rules}
	c.JSON(http.StatusOK, &data)
}

func stringToRules(respStr []string) []Rule{
	var grosSexe []Rule
	for _, str := range respStr {
		splitted := strings.Split(str, " ")
		if len(splitted) > 3 && splitted[2] == "-p" {
			rule := Rule{
				Mproto: splitted[3],
				Pproto: splitted[5],
				Dport: splitted[7],
				Dest: splitted[11],
			}
			grosSexe = append(grosSexe, rule)
		}
	}

	return grosSexe
}

// RenameChain PUT /mvchain/{table}/{oldname}/{newname}/
func RenameChain(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.New()
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

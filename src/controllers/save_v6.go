package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SaveRulesV6 GET /save_v6/
func (s *SaveStruct) SaveRulesV6(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	err := os.MkdirAll("/etc/iptables/", 0755)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	stdout, err := exec.Command("ip6tables-save").Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	err = ioutil.WriteFile("/etc/iptables/rules.v6", stdout, 0644) // nolint: gosec
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	err = os.MkdirAll(s.SavePath, 0755)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	currentTime := time.Now().Local()
	dstFile := []string{s.SavePath, "rules.v6.", currentTime.Format("2006-01-02"), ".", currentTime.Format("15-04-05")}
	cmd := exec.Command("cp", "/etc/iptables/rules.v6", strings.Join(dstFile, ""))
	err = cmd.Run()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintln(w, strings.Join(dstFile, ""))
}

// RestoreRulesV6 GET /restore_v6/{file}
func RestoreRulesV6(c *gin.Context) {
	w := c.Writer
	r := c.Request

	if !checkRole(c) {
		return
	}

	err := exec.Command("ip6tables-restore", r.URL.Query().Get("file")).Run()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

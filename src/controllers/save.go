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

// SaveRules GET /save/
func (s *SaveStruct) SaveRules(c *gin.Context) {
	w := c.Writer

	err := os.MkdirAll("/etc/iptables/", 0755)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	stdout, err := exec.Command("iptables-save").Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	err = ioutil.WriteFile("/etc/iptables/rules.v4", stdout, 0644) // nolint: gosec
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
	dstFile := []string{s.SavePath, "rules.v4.", currentTime.Format("2006-01-02"), ".", currentTime.Format("15-04-05")}
	cmd := exec.Command("cp", "/etc/iptables/rules.v4", strings.Join(dstFile, ""))
	err = cmd.Run()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintln(w, strings.Join(dstFile, ""))
}

// RestoreRules GET /restore/{file}
func RestoreRules(c *gin.Context) {
	w := c.Writer
	r := c.Request

	err := exec.Command("iptables-restore", r.URL.Query().Get("file")).Run()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

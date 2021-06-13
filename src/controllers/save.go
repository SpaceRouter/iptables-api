package controllers

import (
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"iptables-api/forms"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SaveRules GET /save/
func (s *SaveStruct) SaveRules(c *gin.Context) {
	err := os.MkdirAll("/etc/iptables/", 0755)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	stdout, err := exec.Command("iptables-save").Output()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	err = ioutil.WriteFile("/etc/iptables/rules.v4", stdout, 0644) // nolint: gosec
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	err = os.MkdirAll(s.SavePath, 0755)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	currentTime := time.Now().Local()
	dstFile := []string{s.SavePath, "rules.v4.", currentTime.Format("2006-01-02"), ".", currentTime.Format("15-04-05")}
	cmd := exec.Command("cp", "/etc/iptables/rules.v4", strings.Join(dstFile, ""))
	err = cmd.Run()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}

	// fmt.Fprintln(w, strings.Join(dstFile, ""))
}

// RestoreRules GET /restore/{file}
func RestoreRules(c *gin.Context) {
	err := exec.Command("iptables-restore", c.Query("file")).Run()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
}

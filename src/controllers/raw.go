package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jeremmfr/go-iptables/iptables"
	"iptables-api/forms"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

func rawGenerate(c *gin.Context) []string {
	var specEnd []string

	if c.Query("sports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--sports", c.Query("sports"))
	}
	if c.Query("dports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--dports", c.Query("dports"))
	}
	if c.Query("notrack") != "" {
		specEnd = append(specEnd, "--notrack")
	}
	if (c.Query("tcpflag1") != "") && (c.Query("tcpflag2") != "") && (c.Param("proto") == tcpStr) {
		tcpflag := []string{"--tcp-flags", c.Query("tcpflag1"), c.Query("tcpflag2")}
		specEnd = append(specEnd, tcpflag...)
	}
	if c.Query("tcpmss") != "" {
		specEnd = append(specEnd, "-m", "tcpmss", "--mss", c.Query("tcpmss"))
	}
	if c.Param("iface_in") != "*" {
		specEnd = append(specEnd, "-i", c.Param("iface_in"))
	}
	if c.Param("iface_out") != "*" {
		specEnd = append(specEnd, "-o", c.Param("iface_out"))
	}
	srcRange := strings.Contains(c.Param("source"), "-")
	dstRange := strings.Contains(c.Param("destination"), "-")
	ruleSpecs := []string{"-p", c.Param("proto")}
	if srcRange {
		ruleSpecs = append(ruleSpecs, "-m", "iprange", "--src-range", strings.ReplaceAll(c.Param("source"), "_32", ""))
	} else {
		ruleSpecs = append(ruleSpecs, "-s", strings.ReplaceAll(c.Param("source"), "_", "/"))
	}
	if dstRange {
		ruleSpecs = append(ruleSpecs, "-m", "iprange", "--dst-range", strings.ReplaceAll(c.Param("destination"), "_32", ""))
	} else {
		ruleSpecs = append(ruleSpecs, "-d", strings.ReplaceAll(c.Param("destination"), "_", "/"))
	}
	ruleSpecs = append(ruleSpecs, "-j", c.Param("action"))
	if (c.Query("log-prefix") != "") && c.Param("action") == logAct {
		ruleSpecs = append(ruleSpecs, "--log-prefix", c.Query("log-prefix"))
	}
	ruleSpecs = append(ruleSpecs, specEnd...)

	return ruleSpecs
}

func checkPosRaw(c *gin.Context) ([]string, error) {
	var linenumber []string

	line := []string{c.Param("action"), c.Param("proto"), "--"}
	line = append(line, c.Param("iface_in"), c.Param("iface_out"))

	srcRange := strings.Contains(c.Param("source"), "-")
	if srcRange {
		line = append(line, "0.0.0.0/0")
	} else {
		source32 := strings.Contains(c.Param("source"), "_32")
		if source32 {
			line = append(line, strings.ReplaceAll(c.Param("source"), "_32", ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("source"), "_", "/"))
		}
	}

	dstRange := strings.Contains(c.Param("destination"), "-")
	if dstRange {
		line = append(line, "0.0.0.0/0")
	} else {
		destination32 := strings.Contains(c.Param("destination"), "_32")
		if destination32 {
			line = append(line, strings.ReplaceAll(c.Param("destination"), "_32", ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("destination"), "_", "/"))
		}
	}
	if srcRange {
		line = append(line, "source", "IP", "range", strings.ReplaceAll(c.Param("source"), "_32", ""))
	}
	if dstRange {
		line = append(line, "destination", "IP", "range", strings.ReplaceAll(c.Param("destination"), "_32", ""))
	}
	if c.Query("sports") != "" {
		line = append(line, "multiport", "sports", c.Query("sports"))
	}
	if c.Query("dports") != "" {
		line = append(line, "multiport", "dports", c.Query("dports"))
	}
	if (c.Query("tcpflag1") != "") && (c.Query("tcpflag2") != "") && (c.Param("proto") == tcpStr) {
		line = append(line, tcpStr)
		flags := ""
		if c.Query("tcpflag1") == SYNStr {
			flags = "flags:0x02/"
		}
		if (c.Query("tcpflag1") == defaultFlagsMask) || (c.Query("tcpflag1") == defaultFlagsMask2) {
			flags = "flags:0x17/"
		}
		if c.Query("tcpflag2") == SYNStr {
			flags = strings.Join([]string{flags, "0x02"}, "")
		}
		line = append(line, flags)
	}
	if c.Query("tcpmss") != "" {
		line = append(line, "tcpmss", "match", c.Query("tcpmss"))
	}
	if (c.Query("log-prefix") != "") && c.Param("action") == logAct {
		line = append(line, "LOG", "flags", "0", "level", "4", "prefix", strings.Join([]string{"\"", c.Query("log-prefix"), "\""}, ""))
	}
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	args := []string{"-t", "raw", "-vnL", c.Param("chain"), "--line-numbers"}
	if ipt.HasWait {
		args = append(args, "--wait")
	}
	raws, err := ipt.ExecuteList(args)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(raws); i++ {
		rawsSlice := strings.Fields(raws[i])
		rawsSliceNoVerb := rawsSlice[3:]
		if reflect.DeepEqual(line, rawsSliceNoVerb) {
			linenumber = append(linenumber, rawsSlice[0])
		}
	}

	return linenumber, nil
}

// AddRaw PUT /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func AddRaw(c *gin.Context) {
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
	rulespecs := rawGenerate(c)
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if c.Query("position") != "" {
		position, err := strconv.Atoi(c.Query("position"))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
				Ok:      false,
				Message: err.Error(),
			})
			return
		}
		respErr = ipt.Insert("raw", c.Param("chain"), position, rulespecs...)
	} else {
		respErr = ipt.Append("raw", c.Param("chain"), rulespecs...)
	}
	if respErr != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: respErr.Error(),
		})
		return
	}
}

// DelRaw DELETE /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func DelRaw(c *gin.Context) {

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
	rulespecs := rawGenerate(c)
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respErr = ipt.Delete("raw", c.Param("chain"), rulespecs...)
	if respErr != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: respErr.Error(),
		})
		return
	}
}

// CheckRaw GET /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func CheckRaw(c *gin.Context) {
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
	rulespecs := rawGenerate(c)
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if c.Query("position") != "" {
		if c.Query("tcpflag1") != "" {
			if (c.Query("tcpflag1") != defaultFlagsMask) && (c.Query("tcpflag1") != SYNStr) && (c.Query("tcpflag1") != defaultFlagsMask2) {
				c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
					Ok:      false,
					Message: fmt.Sprint("tcpflag", c.Query("tcpflag1"), "and position not compatible"),
				})
				return
			}
		}
		if c.Query("tcpflag2") != "" {
			if c.Query("tcpflag2") != SYNStr {
				c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
					Ok:      false,
					Message: fmt.Sprint("tcpflag", c.Query("tcpflag2"), "and position not compatible"),
				})
				return
			}
		}
		posRaw, err := checkPosRaw(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
				Ok:      false,
				Message: err.Error(),
			})
			return
		}
		switch {
		case len(posRaw) == 0:
			c.AbortWithStatusJSON(http.StatusNotFound, forms.BasicResponse{
				Ok:      false,
				Message: "NotFound",
			})
			return
		case len(posRaw) != 1:
			c.AbortWithStatusJSON(http.StatusConflict, forms.BasicResponse{
				Ok:      false,
				Message: "Conflict",
			})
			return
		case posRaw[0] == c.Query("position"):
			return
		default:
			c.AbortWithStatusJSON(http.StatusNotFound, forms.BasicResponse{
				Ok:      false,
				Message: "NotFound",
			})
			return
		}
	} else {
		respStr, respErr := ipt.Exists("raw", c.Param("chain"), rulespecs...)
		if respErr != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
				Ok:      false,
				Message: respErr.Error(),
			})
			return
		}
		if !respStr {
			c.AbortWithStatusJSON(http.StatusNotFound, forms.BasicResponse{
				Ok:      false,
				Message: "NotFound",
			})
			return
		}
	}
}

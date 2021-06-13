package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/jeremmfr/go-iptables/iptables"
	"iptables-api/forms"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

func ruleGenerate(c *gin.Context) []string {
	r := c.Request

	var specEnd []string

	if r.URL.Query().Get("sports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--dports", r.URL.Query().Get("dports"))
	}
	if r.URL.Query().Get("state") != "" {
		specEnd = append(specEnd, "-m", "state", "--state", r.URL.Query().Get("state"))
	}
	if r.URL.Query().Get("fragment") != "" {
		specEnd = append(specEnd, "-f")
	}
	if r.URL.Query().Get("icmptype") != "" {
		specEnd = append(specEnd, "--icmp-type", r.URL.Query().Get("icmptype"))
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
	if (r.URL.Query().Get("log-prefix") != "") && c.Param("action") == logAct {
		ruleSpecs = append(ruleSpecs, "--log-prefix", r.URL.Query().Get("log-prefix"))
	}
	ruleSpecs = append(ruleSpecs, specEnd...)

	return ruleSpecs
}

func checkPosRules(c *gin.Context) ([]string, error) {
	var linenumber []string

	r := c.Request

	line := []string{c.Param("action"), c.Param("proto")}
	if r.URL.Query().Get("fragment") != "" {
		line = append(line, "-f")
	} else {
		line = append(line, "--")
	}
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
	if r.URL.Query().Get("sports") != "" {
		line = append(line, "multiport", "sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		line = append(line, "multiport", "dports", r.URL.Query().Get("dports"))
	}
	if r.URL.Query().Get("icmptype") != "" {
		line = append(line, "icmptype", r.URL.Query().Get("icmptype"))
	}
	if (r.URL.Query().Get("log-prefix") != "") && c.Param("action") == logAct {
		line = append(line, "LOG", "flags", "0", "level", "4", "prefix", strings.Join([]string{"\"", r.URL.Query().Get("log-prefix"), "\""}, ""))
	}
	if c.Param("action") == "REJECT" {
		line = append(line, "reject-with", "icmp-port-unreachable")
	}
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	args := []string{"-t", "filter", "-vnL", c.Param("chain"), "--line-numbers"}
	if ipt.HasWait {
		args = append(args, "--wait")
	}
	rules, err := ipt.ExecuteList(args)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(rules); i++ {
		rulesSlice := strings.Fields(rules[i])
		rulesSliceNoVerb := rulesSlice[3:]
		if reflect.DeepEqual(line, rulesSliceNoVerb) {
			linenumber = append(linenumber, rulesSlice[0])
		}
	}

	return linenumber, nil
}

// AddRules PUT /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func AddRules(c *gin.Context) {
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

	rulespecs := ruleGenerate(c)
	ipt, err := iptables.New()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
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
		respErr = ipt.Insert("filter", c.Param("chain"), position, rulespecs...)
	} else {
		respErr = ipt.Append("filter", c.Param("chain"), rulespecs...)
	}
	if respErr != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: respErr.Error(),
		})
		return
	}
}

// DelRules DELETE /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func DelRules(c *gin.Context) {
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
			Message: "Unauthorized",
		})
		return
	}

	rulespecs := ruleGenerate(c)
	ipt, err := iptables.New()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respErr = ipt.Delete("filter", c.Param("chain"), rulespecs...)
	if respErr != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: respErr.Error(),
		})
		return
	}
}

// CheckRules GET /rules/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func CheckRules(c *gin.Context) {
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

	rulespecs := ruleGenerate(c)
	ipt, err := iptables.New()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
			Ok:      false,
			Message: err.Error(),
		})
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if c.Query("position") != "" {
		posRules, err := checkPosRules(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
				Ok:      false,
				Message: err.Error(),
			})
			return
		}
		switch {
		case len(posRules) == 0:
			c.AbortWithStatusJSON(http.StatusNotFound, forms.BasicResponse{
				Ok:      false,
				Message: "NotFound",
			})
			return
		case len(posRules) != 1:
			c.AbortWithStatusJSON(http.StatusConflict, forms.BasicResponse{
				Ok:      false,
				Message: "Conflict",
			})
			return
		case posRules[0] == c.Query("position"):
			c.JSON(http.StatusOK, forms.BasicResponse{
				Ok:      true,
				Message: "",
			})
			return
		default:
			c.AbortWithStatusJSON(http.StatusConflict, forms.BasicResponse{
				Ok:      false,
				Message: "Conflict",
			})
			return
		}
	} else {
		respStr, respErr := ipt.Exists("filter", c.Param("chain"), rulespecs...)
		if respErr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
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

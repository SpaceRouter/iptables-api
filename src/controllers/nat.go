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

func dnatGenerate(c *gin.Context) []string {

	rulespecs := []string{"-p", c.Param("proto"), "-i", c.Param("iface")}
	if c.Query("except") == trueStr {
		rulespecs = append(rulespecs, "!")
	}
	srcRange := strings.Contains(c.Param("source"), "-")
	dstRange := strings.Contains(c.Param("destination"), "-")
	if srcRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--src-range", strings.ReplaceAll(c.Param("source"), "_32", ""))
	} else {
		rulespecs = append(rulespecs, "-s", strings.ReplaceAll(c.Param("source"), "_", "/"))
	}
	if dstRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--dst-range", strings.ReplaceAll(c.Param("destination"), "_32", ""))
	} else {
		rulespecs = append(rulespecs, "-d", strings.ReplaceAll(c.Param("destination"), "_", "/"))
	}
	rulespecs = append(rulespecs, "-j", "DNAT", "--to-destination", c.Param("nat_final"))
	if c.Query("dport") != "" {
		rulespecs = append(rulespecs, "--dport", c.Query("dport"))
	}
	if c.Query("nth_every") != "" {
		rulespecs = append(rulespecs, "-m", "statistic", "--mode", "nth", "--every", c.Query("nth_every"), "--packet", c.Query("nth_packet"))
	}

	return rulespecs
}

func snatGenerate(c *gin.Context) []string {

	rulespecs := []string{"-p", c.Param("proto"), "-o", c.Param("iface")}
	srcRange := strings.Contains(c.Param("source"), "-")
	dstRange := strings.Contains(c.Param("destination"), "-")
	if srcRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--src-range", strings.ReplaceAll(c.Param("source"), "_32", ""))
	} else {
		rulespecs = append(rulespecs, "-s", strings.ReplaceAll(c.Param("source"), "_", "/"))
	}
	if c.Query("except") == trueStr {
		rulespecs = append(rulespecs, "!")
	}
	if dstRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--dst-range", strings.ReplaceAll(c.Param("destination"), "_32", ""))
	} else {
		rulespecs = append(rulespecs, "-d", strings.ReplaceAll(c.Param("destination"), "_", "/"))
	}
	rulespecs = append(rulespecs, "-j", "SNAT", "--to-source", c.Param("nat_final"))
	if c.Query("dport") != "" {
		rulespecs = append(rulespecs, "--dport", c.Query("dport"))
	}
	if c.Query("nth_every") != "" {
		rulespecs = append(rulespecs, "-m", "statistic", "--mode", "nth", "--every", c.Query("nth_every"), "--packet", c.Query("nth_packet"))
	}

	return rulespecs
}

// CheckPosNat function
func CheckPosNat(c *gin.Context) ([]string, error) {
	var linenumber []string
	var line []string

	if c.Param("action") == dnatAct {
		line = append(line, "DNAT", c.Param("proto"), "--", c.Param("iface"), "*")
	}
	if c.Param("action") == snatAct {
		line = append(line, "SNAT", c.Param("proto"), "--", "*", c.Param("iface"))
	}
	source32 := strings.Contains(c.Param("source"), "_32")
	destination32 := strings.Contains(c.Param("destination"), "_32")

	if source32 {
		if (c.Param("action") == dnatAct) && (c.Query("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.ReplaceAll(c.Param("source"), "_32", "")}, ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("source"), "_32", ""))
		}
	} else {
		if (c.Param("action") == dnatAct) && (c.Query("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.ReplaceAll(c.Param("source"), "_", "/")}, ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("source"), "_", "/"))
		}
	}
	if destination32 {
		if (c.Param("action") == snatAct) && (c.Query("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.ReplaceAll(c.Param("destination"), "_32", "")}, ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("destination"), "_32", ""))
		}
	} else {
		if (c.Param("action") == snatAct) && (c.Query("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.ReplaceAll(c.Param("destination"), "_", "/")}, ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("destination"), "_", "/"))
		}
	}
	if c.Query("dport") != "" {
		line = append(line, "tcp", strings.Join([]string{"dpt:", c.Query("dport")}, ""))
	}
	if c.Query("nth_every") != "" {
		if c.Query("nth_packet") == "0" {
			line = append(line, "statistic", "mode", "nth", "every", c.Query("nth_every"))
		} else {
			line = append(line, "statistic", "mode", "nth", "every", c.Query("nth_every"), "packet", c.Query("nth_packet"))
		}
	}
	line = append(line, strings.Join([]string{"to:", c.Param("nat_final")}, ""))

	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	args := []string{"-t", "nat", "-vnL", c.Param("chain"), "--line-numbers"}
	if ipt.HasWait {
		args = append(args, "--wait")
	}
	nats, err := ipt.ExecuteList(args)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(nats); i++ {
		natsSlice := strings.Fields(nats[i])
		natsSliceNoVerb := natsSlice[3:]
		if reflect.DeepEqual(line, natsSliceNoVerb) {
			linenumber = append(linenumber, natsSlice[0])
		}
	}

	return linenumber, nil
}

// AddNat PUT /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func AddNat(c *gin.Context) {
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

	var rulespecs []string
	if (c.Query("nth_every") != "") || (c.Query("nth_packet") != "") {
		if c.Query("nth_every") == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
				Ok:      false,
				Message: "Missing nth every",
			})
			return
		}
		if c.Query("nth_packet") == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
				Ok:      false,
				Message: "Missing nth packet",
			})
			return
		}
	}
	switch c.Param("action") {
	case dnatAct:
		rulespecs = dnatGenerate(c)
	case snatAct:
		rulespecs = snatGenerate(c)
	default:
		c.AbortWithStatusJSON(http.StatusNotFound, forms.BasicResponse{
			Ok:      false,
			Message: "NotFound",
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
		respErr = ipt.Insert("nat", c.Param("chain"), position, rulespecs...)
	} else {
		respErr = ipt.Append("nat", c.Param("chain"), rulespecs...)
	}
	if respErr != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: respErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, forms.BasicResponse{
		Ok:      true,
		Message: "",
	})
	return
}

// DelNat DELETE /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func DelNat(c *gin.Context) {
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

	var rulespecs []string
	if (c.Query("nth_every") != "") || (c.Query("nth_packet") != "") {
		if c.Query("nth_every") == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
				Ok:      false,
				Message: "Missing nth every",
			})
			return
		}
		if c.Query("nth_packet") == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
				Ok:      false,
				Message: "Missing nth packet",
			})
			return
		}
	}
	switch c.Param("action") {
	case dnatAct:
		rulespecs = dnatGenerate(c)
	case snatAct:
		rulespecs = snatGenerate(c)
	default:
		c.AbortWithStatusJSON(http.StatusNotFound, forms.BasicResponse{
			Ok:      false,
			Message: "NotFound",
		})
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respErr = ipt.Delete("nat", c.Param("chain"), rulespecs...)
	if respErr != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
			Ok:      false,
			Message: respErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, forms.BasicResponse{
		Ok:      true,
		Message: "",
	})
	return
}

// CheckNat GET /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func CheckNat(c *gin.Context) {
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
	if c.Query("position") != "" {
		posNat, err := CheckPosNat(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, forms.BasicResponse{
				Ok:      false,
				Message: err.Error(),
			})
			return
		}
		switch {
		case len(posNat) == 0:
			c.AbortWithStatusJSON(http.StatusNotFound, forms.BasicResponse{
				Ok:      false,
				Message: "NotFound",
			})
			return
		case len(posNat) != 1:
			c.AbortWithStatusJSON(http.StatusConflict, forms.BasicResponse{
				Ok:      false,
				Message: "Conflict",
			})
			return
		case posNat[0] == c.Query("position"):
			return
		default:
			c.AbortWithStatusJSON(http.StatusNotFound, forms.BasicResponse{
				Ok:      false,
				Message: "NotFound",
			})
			return
		}
	}
	var rulespecs []string
	if (c.Query("nth_every") != "") || (c.Query("nth_packet") != "") {
		if c.Query("nth_every") == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
				Ok:      false,
				Message: "Missing nth every",
			})
			return
		}
		if c.Query("nth_packet") == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, forms.BasicResponse{
				Ok:      false,
				Message: "Missing nth packet",
			})
			return
		}
	}
	switch c.Param("action") {
	case dnatAct:
		rulespecs = dnatGenerate(c)
	case snatAct:
		rulespecs = snatGenerate(c)
	default:
		c.AbortWithStatusJSON(http.StatusNotFound, forms.BasicResponse{
			Ok:      false,
			Message: "NotFound",
		})
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respStr, respErr := ipt.Exists("nat", c.Param("chain"), rulespecs...)
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
	}
	c.AbortWithStatusJSON(http.StatusOK, forms.BasicResponse{
		Ok:      true,
		Message: "Ok",
	})

}

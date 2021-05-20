package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jeremmfr/go-iptables/iptables"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

func rawGenerate(c *gin.Context) []string {
	r := c.Request

	var specEnd []string

	if r.URL.Query().Get("sports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		specEnd = append(specEnd, "-m", "multiport", "--dports", r.URL.Query().Get("dports"))
	}
	if r.URL.Query().Get("notrack") != "" {
		specEnd = append(specEnd, "--notrack")
	}
	if (r.URL.Query().Get("tcpflag1") != "") && (r.URL.Query().Get("tcpflag2") != "") && (c.Param("proto") == tcpStr) {
		tcpflag := []string{"--tcp-flags", r.URL.Query().Get("tcpflag1"), r.URL.Query().Get("tcpflag2")}
		specEnd = append(specEnd, tcpflag...)
	}
	if r.URL.Query().Get("tcpmss") != "" {
		specEnd = append(specEnd, "-m", "tcpmss", "--mss", r.URL.Query().Get("tcpmss"))
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

func checkPosRaw(c *gin.Context) ([]string, error) {
	r := c.Request

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
	if r.URL.Query().Get("sports") != "" {
		line = append(line, "multiport", "sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		line = append(line, "multiport", "dports", r.URL.Query().Get("dports"))
	}
	if (r.URL.Query().Get("tcpflag1") != "") && (r.URL.Query().Get("tcpflag2") != "") && (c.Param("proto") == tcpStr) {
		line = append(line, tcpStr)
		flags := ""
		if r.URL.Query().Get("tcpflag1") == SYNStr {
			flags = "flags:0x02/"
		}
		if (r.URL.Query().Get("tcpflag1") == defaultFlagsMask) || (r.URL.Query().Get("tcpflag1") == defaultFlagsMask2) {
			flags = "flags:0x17/"
		}
		if r.URL.Query().Get("tcpflag2") == SYNStr {
			flags = strings.Join([]string{flags, "0x02"}, "")
		}
		line = append(line, flags)
	}
	if r.URL.Query().Get("tcpmss") != "" {
		line = append(line, "tcpmss", "match", r.URL.Query().Get("tcpmss"))
	}
	if (r.URL.Query().Get("log-prefix") != "") && c.Param("action") == logAct {
		line = append(line, "LOG", "flags", "0", "level", "4", "prefix", strings.Join([]string{"\"", r.URL.Query().Get("log-prefix"), "\""}, ""))
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
	w := c.Writer
	r := c.Request

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rulespecs := rawGenerate(c)
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		position, err := strconv.Atoi(r.URL.Query().Get("position"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		respErr = ipt.Insert("raw", c.Param("chain"), position, rulespecs...)
	} else {
		respErr = ipt.Append("raw", c.Param("chain"), rulespecs...)
	}
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// DelRaw DELETE /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func DelRaw(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rulespecs := rawGenerate(c)
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respErr = ipt.Delete("raw", c.Param("chain"), rulespecs...)
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// CheckRaw GET /raw/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00&tcpflag1=XYZ&tcpflag2=Y&notrack=true
func CheckRaw(c *gin.Context) {
	w := c.Writer
	r := c.Request

	if !checkRole(c) {
		return
	}

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rulespecs := rawGenerate(c)
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		if r.URL.Query().Get("tcpflag1") != "" {
			if (r.URL.Query().Get("tcpflag1") != defaultFlagsMask) && (r.URL.Query().Get("tcpflag1") != SYNStr) && (r.URL.Query().Get("tcpflag1") != defaultFlagsMask2) {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, "tcpflag", r.URL.Query().Get("tcpflag1"), "and position not compatible")
				return
			}
		}
		if r.URL.Query().Get("tcpflag2") != "" {
			if r.URL.Query().Get("tcpflag2") != SYNStr {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, "tcpflag", r.URL.Query().Get("tcpflag2"), "and position not compatible")
				return
			}
		}
		posRaw, err := checkPosRaw(c)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		switch {
		case len(posRaw) == 0:
			w.WriteHeader(http.StatusNotFound)
			return
		case len(posRaw) != 1:
			w.WriteHeader(http.StatusConflict)
			return
		case posRaw[0] == r.URL.Query().Get("position"):
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	} else {
		respStr, respErr := ipt.Exists("raw", c.Param("chain"), rulespecs...)
		if respErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, respErr)
			return
		}
		if !respStr {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
}

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

func dnatGenerate(c *gin.Context) []string {
	r := c.Request

	rulespecs := []string{"-p", c.Param("proto"), "-i", c.Param("iface")}
	if r.URL.Query().Get("except") == trueStr {
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
	if r.URL.Query().Get("dport") != "" {
		rulespecs = append(rulespecs, "--dport", r.URL.Query().Get("dport"))
	}
	if r.URL.Query().Get("nth_every") != "" {
		rulespecs = append(rulespecs, "-m", "statistic", "--mode", "nth", "--every", r.URL.Query().Get("nth_every"), "--packet", r.URL.Query().Get("nth_packet"))
	}

	return rulespecs
}

func snatGenerate(c *gin.Context) []string {
	r := c.Request

	rulespecs := []string{"-p", c.Param("proto"), "-o", c.Param("iface")}
	srcRange := strings.Contains(c.Param("source"), "-")
	dstRange := strings.Contains(c.Param("destination"), "-")
	if srcRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--src-range", strings.ReplaceAll(c.Param("source"), "_32", ""))
	} else {
		rulespecs = append(rulespecs, "-s", strings.ReplaceAll(c.Param("source"), "_", "/"))
	}
	if r.URL.Query().Get("except") == trueStr {
		rulespecs = append(rulespecs, "!")
	}
	if dstRange {
		rulespecs = append(rulespecs, "-m", "iprange", "--dst-range", strings.ReplaceAll(c.Param("destination"), "_32", ""))
	} else {
		rulespecs = append(rulespecs, "-d", strings.ReplaceAll(c.Param("destination"), "_", "/"))
	}
	rulespecs = append(rulespecs, "-j", "SNAT", "--to-source", c.Param("nat_final"))
	if r.URL.Query().Get("dport") != "" {
		rulespecs = append(rulespecs, "--dport", r.URL.Query().Get("dport"))
	}
	if r.URL.Query().Get("nth_every") != "" {
		rulespecs = append(rulespecs, "-m", "statistic", "--mode", "nth", "--every", r.URL.Query().Get("nth_every"), "--packet", r.URL.Query().Get("nth_packet"))
	}

	return rulespecs
}

// CheckPosNat function
func CheckPosNat(c *gin.Context) ([]string, error) {
	r := c.Request

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
		if (c.Param("action") == dnatAct) && (r.URL.Query().Get("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.ReplaceAll(c.Param("source"), "_32", "")}, ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("source"), "_32", ""))
		}
	} else {
		if (c.Param("action") == dnatAct) && (r.URL.Query().Get("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.ReplaceAll(c.Param("source"), "_", "/")}, ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("source"), "_", "/"))
		}
	}
	if destination32 {
		if (c.Param("action") == snatAct) && (r.URL.Query().Get("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.ReplaceAll(c.Param("destination"), "_32", "")}, ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("destination"), "_32", ""))
		}
	} else {
		if (c.Param("action") == snatAct) && (r.URL.Query().Get("except") == trueStr) {
			line = append(line, strings.Join([]string{"!", strings.ReplaceAll(c.Param("destination"), "_", "/")}, ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("destination"), "_", "/"))
		}
	}
	if r.URL.Query().Get("dport") != "" {
		line = append(line, "tcp", strings.Join([]string{"dpt:", r.URL.Query().Get("dport")}, ""))
	}
	if r.URL.Query().Get("nth_every") != "" {
		if r.URL.Query().Get("nth_packet") == "0" {
			line = append(line, "statistic", "mode", "nth", "every", r.URL.Query().Get("nth_every"))
		} else {
			line = append(line, "statistic", "mode", "nth", "every", r.URL.Query().Get("nth_every"), "packet", r.URL.Query().Get("nth_packet"))
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
	var rulespecs []string
	if (r.URL.Query().Get("nth_every") != "") || (r.URL.Query().Get("nth_packet") != "") {
		if r.URL.Query().Get("nth_every") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth every")
			return
		}
		if r.URL.Query().Get("nth_packet") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth packet")
			return
		}
	}
	switch c.Param("action") {
	case dnatAct:
		rulespecs = dnatGenerate(c)
	case snatAct:
		rulespecs = snatGenerate(c)
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		position, err := strconv.Atoi(r.URL.Query().Get("position"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		respErr = ipt.Insert("nat", c.Param("chain"), position, rulespecs...)
	} else {
		respErr = ipt.Append("nat", c.Param("chain"), rulespecs...)
	}
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// DelNat DELETE /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func DelNat(c *gin.Context) {
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
	var rulespecs []string
	if (r.URL.Query().Get("nth_every") != "") || (r.URL.Query().Get("nth_packet") != "") {
		if r.URL.Query().Get("nth_every") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth every")
			return
		}
		if r.URL.Query().Get("nth_packet") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth packet")
			return
		}
	}
	switch c.Param("action") {
	case dnatAct:
		rulespecs = dnatGenerate(c)
	case snatAct:
		rulespecs = snatGenerate(c)
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respErr = ipt.Delete("nat", c.Param("chain"), rulespecs...)
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// CheckNat GET /nat/{action}/{chain}/{proto}/{iface}/{source}/{destination}/{nat_final}/?dport=00
func CheckNat(c *gin.Context) {
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
	if r.URL.Query().Get("position") != "" {
		posNat, err := CheckPosNat(c)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		switch {
		case len(posNat) == 0:
			w.WriteHeader(http.StatusNotFound)
			return
		case len(posNat) != 1:
			w.WriteHeader(http.StatusConflict)
			return
		case posNat[0] == r.URL.Query().Get("position"):
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	var rulespecs []string
	if (r.URL.Query().Get("nth_every") != "") || (r.URL.Query().Get("nth_packet") != "") {
		if r.URL.Query().Get("nth_every") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth every")
			return
		}
		if r.URL.Query().Get("nth_packet") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Missing nth packet")
			return
		}
	}
	switch c.Param("action") {
	case dnatAct:
		rulespecs = dnatGenerate(c)
	case snatAct:
		rulespecs = snatGenerate(c)
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	respStr, respErr := ipt.Exists("nat", c.Param("chain"), rulespecs...)
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
	if !respStr {
		w.WriteHeader(http.StatusNotFound)
	}
}

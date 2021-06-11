package controllers

/*
func ruleGenerateV6(c *gin.Context) []string {
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
	if r.URL.Query().Get("icmptype") != "" {
		specEnd = append(specEnd, "--icmpv6-type", r.URL.Query().Get("icmptype"))
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
		ruleSpecs = append(ruleSpecs, "-m", "iprange", "--src-range", strings.ReplaceAll(c.Param("source"), "_128", ""))
	} else {
		ruleSpecs = append(ruleSpecs, "-s", strings.ReplaceAll(c.Param("source"), "_", "/"))
	}
	if dstRange {
		ruleSpecs = append(ruleSpecs, "-m", "iprange", "--dst-range", strings.ReplaceAll(c.Param("destination"), "_128", ""))
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

func checkPosRulesV6(c *gin.Context) ([]string, error) {
	r := c.Request
	var linenumber []string

	line := []string{c.Param("action"), c.Param("proto")}
	line = append(line, c.Param("iface_in"), c.Param("iface_out"))

	srcRange := strings.Contains(c.Param("source"), "-")
	if srcRange {
		line = append(line, "::/0")
	} else {
		source128 := strings.Contains(c.Param("source"), "_128")
		if source128 {
			line = append(line, strings.ReplaceAll(c.Param("source"), "_128", ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("source"), "_", "/"))
		}
	}

	dstRange := strings.Contains(c.Param("destination"), "-")
	if dstRange {
		line = append(line, "::/0")
	} else {
		destination128 := strings.Contains(c.Param("destination"), "_128")
		if destination128 {
			line = append(line, strings.ReplaceAll(c.Param("destination"), "_128", ""))
		} else {
			line = append(line, strings.ReplaceAll(c.Param("destination"), "_", "/"))
		}
	}
	if srcRange {
		line = append(line, "source", "IP", "range", strings.ReplaceAll(c.Param("source"), "_128", ""))
	}
	if dstRange {
		line = append(line, "destination", "IP", "range", strings.ReplaceAll(c.Param("destination"), "_128", ""))
	}
	if r.URL.Query().Get("sports") != "" {
		line = append(line, "multiport", "sports", r.URL.Query().Get("sports"))
	}
	if r.URL.Query().Get("dports") != "" {
		line = append(line, "multiport", "dports", r.URL.Query().Get("dports"))
	}
	if r.URL.Query().Get("icmptype") != "" {
		line = append(line, "ipv6-icmptype", r.URL.Query().Get("icmptype"))
	}
	if (r.URL.Query().Get("log-prefix") != "") && c.Param("action") == logAct {
		line = append(line, "LOG", "flags", "0", "level", "4", "prefix", strings.Join([]string{"\"", r.URL.Query().Get("log-prefix"), "\""}, ""))
	}
	ipt, err := iptables.NewWithProtocol(v6)
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

// AddRulesV6 PUT /rules_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func AddRulesV6(c *gin.Context) {
	w := c.Writer
	r := c.Request

	if !checkRole(c) {
		return
	}

	rulespecs := ruleGenerateV6(c)
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
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
		respErr = ipt.Insert("filter", c.Param("chain"), position, rulespecs...)
	} else {
		respErr = ipt.Append("filter", c.Param("chain"), rulespecs...)
	}
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// DelRulesV6 DELETE /rules_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func DelRulesV6(c *gin.Context) {
	w := c.Writer

	if !checkRole(c) {
		return
	}

	rulespecs := ruleGenerateV6(c)
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}

	respErr = ipt.Delete("filter", c.Param("chain"), rulespecs...)
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// CheckRulesV6 GET /rules_v6/{action}/{chain}/{proto}/{iface_in}/{iface_out}/{source}/{destination}/?sports=00&dports=00
func CheckRulesV6(c *gin.Context) {
	w := c.Writer
	r := c.Request

	if !checkRole(c) {
		return
	}

	rulespecs := ruleGenerateV6(c)
	ipt, err := iptables.NewWithProtocol(v6)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ipt.HasWait {
		rulespecs = append(rulespecs, "--wait")
	}
	if r.URL.Query().Get("position") != "" {
		posRules, err := checkPosRulesV6(c)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		switch {
		case len(posRules) == 0:
			w.WriteHeader(http.StatusNotFound)
			return
		case len(posRules) != 1:
			w.WriteHeader(http.StatusConflict)
			return
		case posRules[0] == r.URL.Query().Get("position"):
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	} else {

		respStr, respErr := ipt.Exists("filter", c.Param("chain"), rulespecs...)
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
*/

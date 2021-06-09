package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/jeremmfr/go-iptables/iptables"
	"github.com/spacerouter/sr_auth"
)

var (
	respErr error
)

// Constantes
const (
	v6                iptables.Protocol = iota + 1
	dnatAct           string            = "dnat"
	snatAct           string            = "snat"
	logAct            string            = "LOG"
	trueStr           string            = "true"
	tcpStr            string            = "tcp"
	SYNStr            string            = "SYN"
	defaultFlagsMask  string            = "FIN,SYN,RST,ACK"
	defaultFlagsMask2 string            = "SYN,RST,ACK,FIN"
)

const (
	iptablesRole sr_auth.Role = "iptables"
)

type SaveStruct struct {
	SavePath string
}

func checkRole(c *gin.Context) (bool, error) {
	user, err := sr_auth.ExtractUser(c)
	if err != nil {
		return false, err
	}

	role, err := user.GetRoles()
	if err != nil {
		return false, err
	}

	if *role == iptablesRole {
		return false, nil

	}

	return true, nil
}

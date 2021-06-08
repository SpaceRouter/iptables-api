package forms

import "iptables-api/models"

type ChainListResponse struct {
	Ok      bool
	Message string
	Chains  []models.Chain
}

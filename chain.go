package main

import (
	"fmt"
	"net/http"

	auth "github.com/abbot/go-http-auth"
	"github.com/gorilla/mux"
	"github.com/jeremmfr/go-iptables/iptables"
)

// PUT /chain/{table}/{name}/
func addChain(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}
	}
	vars := mux.Vars(r)

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)

		return
	}
	respErr = ipt.NewChain(vars["table"], vars["name"])
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// DELETE /chain/{table}/{name}/
func delChain(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}
	}
	vars := mux.Vars(r)

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)

		return
	}
	// Clear chain before delete
	respErr = ipt.ClearChain(vars["table"], vars["name"])
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
	// Delete chain
	respErr = ipt.DeleteChain(vars["table"], vars["name"])
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

// GET /chain/{table}/{name}/
func listChain(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}
	}
	vars := mux.Vars(r)

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)

		return
	}
	respStr, respErr := ipt.List(vars["table"], vars["name"])
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
	for i := 0; i < len(respStr); i++ {
		fmt.Fprintln(w, respStr[i])
	}
}

// PUT /mvchain/{table}/{oldname}/{newname}/
func renameChain(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}
	}
	vars := mux.Vars(r)

	ipt, err := iptables.New()
	if err != nil {
		http.Error(w, err.Error(), 500)

		return
	}
	respErr = ipt.RenameChain(vars["table"], vars["oldname"], vars["newname"])
	if respErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, respErr)
	}
}

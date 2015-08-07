// Package whitelist implements IP whitelisting for net/http.
package whitelist

import (
	"errors"
	"net"
	"net/http"
)

var errBadIP = errors.New("invalid ip address")

type Whitelist struct {
	allowed []*net.IPNet
}

// New creates a new Whitelist for the networks.
func New(nets []string) (*Whitelist, error) {
	var wl Whitelist

	for _, i := range nets {
		_, net, err := net.ParseCIDR(i)
		if err != nil {
			return nil, err
		}
		wl.allowed = append(wl.allowed, net)
	}

	return &wl, nil
}
func getRemoteAddress(r *http.Request) (net.IP, error) {
	address, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, errBadIP
	}
	return ip, nil
}

// Handler wraps another Handler.
func (wl *Whitelist) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// we use RemoteAddr so X-F-F will be honored if
		// another middleware changes it
		ip, err := getRemoteAddress(r)
		if err != nil {
			// should this be fatal or should we just skip?
			http.Error(w, "invalid remote address", 400)
			return
		}

		//O(n) - could do a better way, but this handles v6, etc
		for _, n := range wl.allowed {
			if n.Contains(ip) {
				h.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "access denied", 403)
	})
}

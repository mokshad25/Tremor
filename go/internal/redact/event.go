package redact

import (
	"net/netip"
	"strings"

	"github.com/mokshad/tremor/internal/event"
)

// Event redacts an event in place: the message and every attribute value.
// The service name is the routing key and is not redacted (service names
// are configuration, not personal data). Attribute keys are kept, and they
// pick the treatment of their value:
//
//   - secret-looking keys (password, token, authorization, cookie, ...):
//     the whole value becomes <SECRET>, whatever it looks like;
//   - user keys (user, username, user.name, enduser.id, ...): the whole
//     value is tokenized as a username;
//   - a value that is exactly an IP address is tokenized;
//   - anything else goes through the same scanner as messages.
func (r *Redactor) Event(ev *event.Event) {
	ev.Message = r.String(ev.Message)
	for k, v := range ev.Attrs {
		ev.Attrs[k] = r.attr(k, v)
	}
}

// Events redacts a batch in place.
func (r *Redactor) Events(evs []event.Event) {
	for i := range evs {
		r.Event(&evs[i])
	}
}

var secretKeyParts = []string{"password", "passwd", "secret", "token", "authorization", "api_key", "apikey", "api-key", "cookie", "private_key", "credential", "session_key"}

var userAttrKeys = map[string]bool{
	"user": true, "username": true, "user_name": true, "user.name": true, "user.id": true,
	"enduser.id": true, "login": true, "account": true, "usr": true, "user.email": true,
}

func (r *Redactor) attr(key, v string) string {
	if v == "" || strings.HasPrefix(v, "<") {
		return v
	}
	lk := strings.ToLower(key)
	for _, part := range secretKeyParts {
		if strings.Contains(lk, part) { // whatever the value looks like
			r.counts[KindSecret].Add(1)
			return placeholders[KindSecret]
		}
	}
	if isPlaceholder(v) {
		return v
	}
	if userAttrKeys[lk] {
		r.counts[KindUser].Add(1)
		return r.replacement(KindUser, v)
	}
	if _, err := netip.ParseAddr(v); err == nil {
		r.counts[KindIP].Add(1)
		return r.replacement(KindIP, v)
	}
	return r.String(v)
}

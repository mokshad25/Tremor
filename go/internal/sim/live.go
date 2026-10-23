package sim

import (
	"fmt"
	"math/rand/v2"
	"time"
)

// Live attacks for cmd/loadgen -attack: a prelude (history the rule needs,
// sent first) and the attack itself, both relative to now, plus the label.
// Privilege change needs the server's learning period to have passed after
// the prelude: run the server with detect.security.privilege_learn_s set
// below -attack-at for a live demo.

// LiveAttack builds one attack of the given kind starting at `at`.
func LiveAttack(kind string, now, at time.Time, seed uint64) (prelude, attack []Line, label Label, err error) {
	r := rand.New(rand.NewPCG(seed, 0xa77))
	ip := func() string { return fmt.Sprintf("185.%d.%d.%d", r.IntN(256), r.IntN(256), 1+r.IntN(254)) }
	switch kind {
	case "brute_force":
		src, t := ip(), at
		for i := range 25 {
			attack = append(attack, Line{TS: t, Service: "sshd", Level: "INFO",
				Message: fmt.Sprintf("sshd[%d]: Failed password for root from %s port %d ssh2", 20000+i, src, 40000+r.IntN(20000))})
			t = t.Add(2 * time.Second)
		}
		attack = append(attack, Line{TS: t, Service: "sshd", Level: "INFO",
			Message: fmt.Sprintf("sshd[%d]: Accepted password for root from %s port %d ssh2", 20999, src, 40000+r.IntN(20000))})
		label = Label{Type: kind, Variant: "sshd", Service: "sshd", Start: at, End: t, User: "root", Source: src}
	case "credential_stuffing":
		src, t := ip(), at
		for i := range 60 {
			attack = append(attack, Line{TS: t, Service: "auth-service", Level: "WARNING",
				Message: fmt.Sprintf("Login failed user=%s.%s%d@gmail.com ip=%s reason=bad_password", firsts[r.IntN(len(firsts))], lasts[r.IntN(len(lasts))], i, src)})
			t = t.Add(time.Second)
		}
		label = Label{Type: kind, Variant: "single_source", Service: "auth-service", Start: at, End: t, Source: src}
	case "privilege_change":
		for i := range 3 { // the baseline: the ops admin restarts services with sudo
			prelude = append(prelude, Line{TS: now.Add(time.Duration(i) * time.Second), Service: "bastion", Level: "INFO",
				Message: "sudo:   ops.admin : TTY=pts/0 ; PWD=/home/ops.admin ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"})
		}
		attack = []Line{{TS: at, Service: "bastion", Level: "INFO",
			Message: "sudo:   intern.dev : TTY=pts/3 ; PWD=/home/intern.dev ; USER=root ; COMMAND=/bin/bash"}}
		label = Label{Type: kind, Variant: "sudo", Service: "bastion", Start: at, End: at, User: "intern.dev"}
	case "unusual_access":
		// 30 logins over the past 10 days from home, at hours far from now,
		// then a login now from a new address: the account-takeover shape.
		home, victim := "49.36.101.7", "meera.nair"
		usual := (now.UTC().Hour() + 8) % 24
		for d := range 10 {
			for k := range 3 {
				ts := now.UTC().AddDate(0, 0, -10+d).Truncate(24 * time.Hour).Add(time.Duration(usual+k%2) * time.Hour)
				prelude = append(prelude, Line{TS: ts, Service: "auth-service", Level: "INFO",
					Message: fmt.Sprintf("Login succeeded user=%s ip=%s method=password", victim, home)})
			}
		}
		src := ip()
		attack = []Line{{TS: at, Service: "auth-service", Level: "INFO",
			Message: fmt.Sprintf("Login succeeded user=%s ip=%s method=password", victim, src)}}
		label = Label{Type: kind, Variant: "takeover", Service: "auth-service", Start: at, End: at, User: victim, Source: src}
	default:
		err = fmt.Errorf("unknown attack %q (brute_force, credential_stuffing, privilege_change, unusual_access)", kind)
	}
	return prelude, attack, label, err
}

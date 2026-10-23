// Package sim generates synthetic, labelled security traffic: a realistic
// authentication background (employees, admins, an office NAT) with attacks
// mixed in, each carrying a ground-truth label. The offline evaluation
// (cmd/eval -security) and the live attack simulator (cmd/loadgen -attack)
// both use it. Everything is driven by one seeded RNG, so a scenario is
// reproducible byte for byte.
package sim

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"time"
)

// Line is one raw log line (before redaction).
type Line struct {
	TS      time.Time
	Service string
	Level   string
	Message string
}

// Label is the ground truth for one injected attack.
type Label struct {
	Type    string // brute_force | credential_stuffing | privilege_change | unusual_access
	Variant string // e.g. "sshd", "app", "distributed", "sudo", "new_source"
	Service string
	Start   time.Time
	End     time.Time
	User    string // raw; the evaluator tokenizes it with the same key as the redactor
	Source  string // raw IP
}

// Config shapes a scenario.
type Config struct {
	Seed           uint64
	Start          time.Time // midnight UTC of day 0
	Days           int
	Employees      int
	NATEmployees   int // share the office NAT
	Admins         int
	Attacks        bool
	AttackFromDay  int // attacks only from this day (after the learning period)
	AttacksPerType int
}

func DefaultConfig() Config {
	return Config{
		Seed: 7, Start: time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), Days: 21,
		Employees: 600, NATEmployees: 400, Admins: 10,
		Attacks: true, AttackFromDay: 14, AttacksPerType: 10,
	}
}

// OfficeNAT is the shared egress address of the office (documentation range).
const OfficeNAT = "203.0.113.10"

type person struct {
	user    string
	ips     []string // personal / home addresses
	viaNAT  bool
	startH  int // first working hour (UTC)
	spanH   int
	perDay  int
	isAdmin bool
}

type gen struct {
	cfg    Config
	r      *rand.Rand
	lines  []Line
	labels []Label
	people []*person
	admins []*person
	usedIP map[string]bool
	logins map[string][]time.Time // successful logins per user, for picking victims
	hours  map[string][24]int
}

// Generate builds a scenario: lines sorted by time, plus labels.
func Generate(cfg Config) ([]Line, []Label) {
	g := &gen{cfg: cfg, r: rand.New(rand.NewPCG(cfg.Seed, 0x5ec)), usedIP: map[string]bool{},
		logins: map[string][]time.Time{}, hours: map[string][24]int{}}
	g.population()
	for d := range cfg.Days {
		g.normalDay(d)
	}
	slices.SortStableFunc(g.lines, func(a, b Line) int { return a.TS.Compare(b.TS) })
	if cfg.Attacks {
		g.attacks()
		slices.SortStableFunc(g.lines, func(a, b Line) int { return a.TS.Compare(b.TS) })
	}
	return g.lines, g.labels
}

var firsts = []string{"aarav", "priya", "rahul", "ananya", "vikram", "sneha", "arjun", "kavya", "rohan", "meera", "ishaan", "diya", "kabir", "nisha", "aditya", "pooja", "karan", "riya", "siddharth", "tara"}
var lasts = []string{"sharma", "iyer", "patel", "reddy", "nair", "gupta", "khan", "singh", "das", "menon", "rao", "joshi", "bose", "pillai"}

func (g *gen) pick(xs []string) string { return xs[g.r.IntN(len(xs))] }

// publicIP returns a fresh random public address (never the NAT).
func (g *gen) publicIP() string {
	for {
		ip := fmt.Sprintf("%d.%d.%d.%d", []int{49, 103, 106, 117, 122, 157, 182}[g.r.IntN(7)], g.r.IntN(256), g.r.IntN(256), 1+g.r.IntN(254))
		if !g.usedIP[ip] {
			g.usedIP[ip] = true
			return ip
		}
	}
}

// attackerIP is a fresh address in ranges the background never uses.
func (g *gen) attackerIP() string {
	for {
		ip := fmt.Sprintf("%d.%d.%d.%d", []int{45, 89, 185, 193, 194}[g.r.IntN(5)], g.r.IntN(256), g.r.IntN(256), 1+g.r.IntN(254))
		if !g.usedIP[ip] {
			g.usedIP[ip] = true
			return ip
		}
	}
}

func (g *gen) population() {
	seen := map[string]bool{}
	for i := range g.cfg.Employees {
		var u string
		for {
			u = g.pick(firsts) + "." + g.pick(lasts) + fmt.Sprint(g.r.IntN(100))
			if !seen[u] {
				seen[u] = true
				break
			}
		}
		p := &person{user: u, ips: []string{g.publicIP()}, viaNAT: i < g.cfg.NATEmployees,
			startH: 3 + g.r.IntN(3), spanH: 8 + g.r.IntN(3), perDay: 4 + g.r.IntN(4)}
		if g.r.IntN(3) == 0 {
			p.ips = append(p.ips, g.publicIP())
		}
		if g.r.IntN(10) == 0 { // night shift
			p.startH = 15 + g.r.IntN(3)
		}
		if i < g.cfg.Admins {
			p.isAdmin = true
			g.admins = append(g.admins, p)
		}
		g.people = append(g.people, p)
	}
}

func (g *gen) add(ts time.Time, svc, level, msg string) {
	g.lines = append(g.lines, Line{TS: ts, Service: svc, Level: level, Message: msg})
}

func (g *gen) appLogin(ts time.Time, user, ip string, ok bool) {
	if ok {
		g.add(ts, "auth-service", "INFO", fmt.Sprintf("Login succeeded user=%s ip=%s method=password", user, ip))
		g.logins[user] = append(g.logins[user], ts)
		h := g.hours[user]
		h[ts.Hour()]++
		g.hours[user] = h
	} else {
		g.add(ts, "auth-service", "WARNING", fmt.Sprintf("Login failed user=%s ip=%s reason=bad_password", user, ip))
	}
}

func port(r *rand.Rand) int { return 1024 + r.IntN(60000) }

func (g *gen) sshFailed(ts time.Time, user, ip string, invalid bool) {
	pid := 10000 + g.r.IntN(50000)
	if invalid {
		g.add(ts, "sshd", "INFO", fmt.Sprintf("sshd[%d]: Invalid user %s from %s", pid, user, ip))
		g.add(ts, "sshd", "INFO", fmt.Sprintf("sshd[%d]: Failed password for invalid user %s from %s port %d ssh2", pid, user, ip, port(g.r)))
		return
	}
	g.add(ts, "sshd", "INFO", fmt.Sprintf("sshd[%d]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%s  user=%s", pid, ip, user))
	g.add(ts, "sshd", "INFO", fmt.Sprintf("sshd[%d]: Failed password for %s from %s port %d ssh2", pid, user, ip, port(g.r)))
}

func (g *gen) sshAccepted(ts time.Time, user, ip, method string) {
	g.add(ts, "sshd", "INFO", fmt.Sprintf("sshd[%d]: Accepted %s for %s from %s port %d ssh2", 10000+g.r.IntN(50000), method, user, ip, port(g.r)))
	g.logins["ssh:"+user] = append(g.logins["ssh:"+user], ts)
}

// normalDay generates one day of attack-free traffic.
func (g *gen) normalDay(d int) {
	day := g.cfg.Start.AddDate(0, 0, d)
	weekend := day.Weekday() == time.Saturday || day.Weekday() == time.Sunday
	rotationDay := day.Weekday() == time.Wednesday // passwords rotate: many typos
	for _, p := range g.people {
		n := p.perDay
		if weekend {
			n = g.r.IntN(2)
		}
		for range n {
			ts := day.Add(time.Duration(p.startH)*time.Hour + time.Duration(g.r.Int64N(int64(time.Duration(p.spanH)*time.Hour))))
			ip := p.ips[g.r.IntN(len(p.ips))]
			if p.viaNAT && !weekend && g.r.IntN(3) > 0 {
				ip = OfficeNAT
			}
			if g.r.IntN(200) == 0 { // travel, a new ISP, a phone hotspot
				ip = g.publicIP()
			}
			g.typoThenLogin(ts, p.user, ip, 0.04)
		}
		// The office morning rush: NAT users log in at 09:00 IST (03:30 UTC).
		if p.viaNAT && !weekend {
			ts := day.Add(3*time.Hour + 30*time.Minute + time.Duration(g.r.Int64N(int64(30*time.Minute))))
			typo := 0.06
			if rotationDay {
				typo = 0.25
			}
			g.typoThenLogin(ts, p.user, OfficeNAT, typo)
		}
	}
	// Admins: SSH with keys, daily sudo, routine role grants.
	for i, a := range g.admins {
		if weekend && i%2 == 0 {
			continue
		}
		for range 2 + g.r.IntN(3) {
			ts := day.Add(time.Duration(a.startH)*time.Hour + time.Duration(g.r.Int64N(int64(time.Duration(a.spanH)*time.Hour))))
			g.sshAccepted(ts, a.user, a.ips[0], "publickey")
			g.add(ts.Add(time.Minute), "sshd", "INFO", fmt.Sprintf("sudo:   %s : TTY=pts/%d ; PWD=/home/%s ; USER=root ; COMMAND=/usr/bin/systemctl restart %s",
				a.user, g.r.IntN(5), a.user, g.pick([]string{"nginx", "api", "worker", "postgresql"})))
		}
		if i < 3 { // three admins manage roles
			target := g.people[g.cfg.Admins+g.r.IntN(len(g.people)-g.cfg.Admins)].user
			ts := day.Add(time.Duration(a.startH+1)*time.Hour + time.Duration(g.r.IntN(3600))*time.Second)
			role := g.pick([]string{"viewer", "editor", "analyst"})
			g.add(ts, "admin-portal", "INFO", fmt.Sprintf("Role %s granted to user=%s by admin %s", role, target, a.user))
		}
	}
	// Occasional admin password typo on sshd.
	for _, a := range g.admins {
		if g.r.IntN(5) == 0 {
			ts := day.Add(time.Duration(a.startH)*time.Hour + time.Duration(g.r.IntN(3600))*time.Second)
			g.sshFailed(ts, a.user, a.ips[0], false)
			g.sshAccepted(ts.Add(5*time.Second), a.user, a.ips[0], "password")
		}
	}
}

func (g *gen) typoThenLogin(ts time.Time, user, ip string, typo float64) {
	for g.r.Float64() < typo {
		g.appLogin(ts, user, ip, false)
		ts = ts.Add(time.Duration(3+g.r.IntN(20)) * time.Second)
		typo /= 3 // retries usually succeed
	}
	g.appLogin(ts, user, ip, true)
}

// ── attacks ──────────────────────────────────────────────────────────

// slot returns a random attack start in days [AttackFromDay, Days) that
// keeps at least 20 minutes plus the attack's length clear of every other
// attack, so each alert can be attributed to one attack.
func (g *gen) slot(used *[]time.Time, length time.Duration) time.Time {
	gap := 20*time.Minute + length
	for try := 0; ; try++ {
		d := g.cfg.AttackFromDay + g.r.IntN(g.cfg.Days-g.cfg.AttackFromDay)
		ts := g.cfg.Start.AddDate(0, 0, d).Add(time.Duration(g.r.Int64N(int64(22 * time.Hour))))
		ok := true
		for _, u := range *used {
			if ts.Sub(u).Abs() < gap {
				ok = false
				break
			}
		}
		if ok || try > 10000 {
			*used = append(*used, ts)
			return ts
		}
	}
}

func (g *gen) attacks() {
	n := g.cfg.AttacksPerType
	var used []time.Time
	// Brute force: one user, one source, 15-40 attempts in 1-5 minutes.
	for i := range n {
		ip := g.attackerIP()
		ts := g.slot(&used, 10*time.Minute)
		start := ts
		count := 15 + g.r.IntN(26)
		var user string
		var lbl Label
		if i%2 == 0 { // sshd, root or an admin
			user = "root"
			if i%4 == 2 {
				user = g.admins[g.r.IntN(len(g.admins))].user
			}
			for range count {
				g.sshFailed(ts, user, ip, false)
				ts = ts.Add(time.Duration(2+g.r.IntN(8)) * time.Second)
			}
			if i%3 == 0 {
				g.sshAccepted(ts, user, ip, "password")
			}
			lbl = Label{Type: "brute_force", Variant: "sshd", Service: "sshd"}
		} else { // app login against an employee
			user = g.people[g.cfg.Admins+g.r.IntN(len(g.people)-g.cfg.Admins)].user
			for range count {
				g.appLogin(ts, user, ip, false)
				ts = ts.Add(time.Duration(2+g.r.IntN(8)) * time.Second)
			}
			if i%3 == 0 {
				g.appLogin(ts, user, ip, true)
			}
			lbl = Label{Type: "brute_force", Variant: "app", Service: "auth-service"}
		}
		lbl.Start, lbl.End, lbl.User, lbl.Source = start, ts, user, ip
		g.labels = append(g.labels, lbl)
	}
	// Credential stuffing, single source: many usernames, one try each.
	for range n {
		ip := g.attackerIP()
		ts := g.slot(&used, 15*time.Minute)
		start := ts
		for range 40 + g.r.IntN(110) {
			victim := g.pick(firsts) + g.pick([]string{".", "_", ""}) + g.pick(lasts) + fmt.Sprint(g.r.IntN(1000)) + "@" + g.pick([]string{"gmail.com", "yahoo.co.in", "outlook.com"})
			g.appLogin(ts, victim, ip, g.r.IntN(50) == 0)
			ts = ts.Add(time.Duration(1+g.r.IntN(5)) * time.Second)
		}
		g.labels = append(g.labels, Label{Type: "credential_stuffing", Variant: "single_source", Service: "auth-service", Start: start, End: ts, Source: ip})
	}
	// Credential stuffing, distributed ("low and slow"): many sources, each
	// below every per-source threshold.
	for range max(n/2, 1) {
		ts := g.slot(&used, 2*time.Hour)
		dur := time.Duration(60+g.r.IntN(30)) * time.Minute
		sources := 150 + g.r.IntN(150)
		attempts := 300 + g.r.IntN(200)
		ips := make([]string, sources)
		for i := range ips {
			ips[i] = g.attackerIP()
		}
		for range attempts {
			at := ts.Add(time.Duration(g.r.Int64N(int64(dur))))
			victim := g.pick(firsts) + "." + g.pick(lasts) + fmt.Sprint(g.r.IntN(1000)) + "@" + g.pick([]string{"gmail.com", "yahoo.co.in"})
			g.appLogin(at, victim, ips[g.r.IntN(sources)], false)
		}
		g.labels = append(g.labels, Label{Type: "credential_stuffing", Variant: "distributed", Service: "auth-service", Start: ts, End: ts.Add(dur)})
	}
	// Privilege change outside the baseline.
	for i := range n {
		ts := g.slot(&used, time.Minute)
		emp := g.people[g.cfg.Admins+g.r.IntN(len(g.people)-g.cfg.Admins)]
		var lbl Label
		switch i % 3 {
		case 0: // an employee who never used sudo
			g.add(ts, "sshd", "INFO", fmt.Sprintf("sudo:   %s : TTY=pts/%d ; PWD=/home/%s ; USER=root ; COMMAND=/bin/bash", emp.user, g.r.IntN(5), emp.user))
			lbl = Label{Variant: "sudo", Service: "sshd", User: emp.user}
		case 1: // a role admin grants admin (they only ever granted viewer/editor)
			a := g.admins[g.r.IntN(3)]
			g.add(ts, "admin-portal", "INFO", fmt.Sprintf("Role admin granted to user=%s by admin %s", emp.user, a.user))
			lbl = Label{Variant: "role_admin", Service: "admin-portal", User: a.user}
		default: // someone outside the role team grants roles
			a := g.admins[3+g.r.IntN(len(g.admins)-3)]
			g.add(ts, "admin-portal", "INFO", fmt.Sprintf("Group membership changed: user=%s added to group wheel by admin %s", emp.user, a.user))
			lbl = Label{Variant: "group_wheel", Service: "admin-portal", User: a.user}
		}
		lbl.Type, lbl.Start, lbl.End = "privilege_change", ts, ts
		g.labels = append(g.labels, lbl)
	}
	// Unusual access: a known user from a new source, or at an odd hour.
	for i := range n {
		ts := g.slot(&used, time.Minute)
		victim := g.victim(ts, 25)
		if victim == nil {
			continue
		}
		var lbl Label
		switch i % 3 {
		case 0:
			ip := g.attackerIP()
			g.appLogin(ts, victim.user, ip, true)
			lbl = Label{Variant: "new_source", Source: ip}
		case 2: // account takeover: a new source at an hour the user never works
			h := (victim.startH + victim.spanH/2 + 12) % 24
			at := time.Date(ts.Year(), ts.Month(), ts.Day(), h, g.r.IntN(60), 0, 0, time.UTC)
			ip := g.attackerIP()
			g.appLogin(at, victim.user, ip, true)
			ts = at
			lbl = Label{Variant: "takeover", Source: ip}
		default:
			h := (victim.startH + victim.spanH/2 + 12) % 24 // opposite side of the clock
			at := time.Date(ts.Year(), ts.Month(), ts.Day(), h, g.r.IntN(60), 0, 0, time.UTC)
			ip := victim.ips[0]
			g.appLogin(at, victim.user, ip, true)
			ts = at
			lbl = Label{Variant: "unusual_hour", Source: ip}
		}
		lbl.Type, lbl.Service, lbl.User, lbl.Start, lbl.End = "unusual_access", "auth-service", victim.user, ts, ts
		g.labels = append(g.labels, lbl)
	}
}

// victim picks an employee with at least minHistory successful logins
// before ts (so the unusual-access rule has a history to compare with).
func (g *gen) victim(ts time.Time, minHistory int) *person {
	for range 1000 {
		p := g.people[g.cfg.Admins+g.r.IntN(len(g.people)-g.cfg.Admins)]
		n := 0
		for _, t := range g.logins[p.user] {
			if t.Before(ts) {
				n++
			}
		}
		if n >= minHistory {
			return p
		}
	}
	return nil
}

// Summary counts lines per service.
func Summary(lines []Line) string {
	c := map[string]int{}
	for _, l := range lines {
		c[l.Service]++
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(c)) {
		parts = append(parts, fmt.Sprintf("%s=%d", k, c[k]))
	}
	return strings.Join(parts, " ")
}

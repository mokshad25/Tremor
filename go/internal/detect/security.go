package detect

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/redact"
)

// Security rule signal types (MITRE ATT&CK techniques are on each alert).
const (
	SignalBruteForce         SignalType = "BRUTE_FORCE"
	SignalCredentialStuffing SignalType = "CREDENTIAL_STUFFING"
	SignalPrivilegeChange    SignalType = "PRIVILEGE_CHANGE"
	SignalUnusualAccess      SignalType = "UNUSUAL_ACCESS"
)

// SecurityConfig holds the security rules' thresholds. The defaults and
// the reasoning behind each are in docs/phase5-security.md.
type SecurityConfig struct {
	Enabled bool `yaml:"enabled"`

	// Brute force (T1110.001): failures for ONE user from ONE source.
	BruteForceWindowS   int `yaml:"brute_force_window_s"`
	BruteForceThreshold int `yaml:"brute_force_threshold"`
	// Brute force from one source across many accounts (an SSH dictionary
	// run: admin, root, test, pi, ...), counted per source in the same
	// window, with the stuffing rule's failure-ratio guard.
	SourceFailThreshold int `yaml:"source_fail_threshold"`

	// Credential stuffing (T1110.004), single source: many distinct users
	// failing from one source, AND most of that source's attempts failing.
	StuffingWindowS         int     `yaml:"stuffing_window_s"`
	StuffingMinUsers        int     `yaml:"stuffing_min_users"`
	StuffingMinFailureRatio float64 `yaml:"stuffing_min_failure_ratio"` // the NAT guard
	// AllowedSources are raw IPs (e.g. a known office NAT) exempt from the
	// single-source rule. They are tokenized with the HMAC key at startup;
	// the raw values are never stored with events.
	AllowedSources []string `yaml:"allowed_sources"`

	// Credential stuffing, distributed ("low and slow"): distinct failing
	// users per window far above the service's learned baseline.
	DistributedWindowS    int     `yaml:"distributed_window_s"`
	DistributedEvalS      int     `yaml:"distributed_eval_s"`
	DistributedMinUsers   int     `yaml:"distributed_min_users"`
	DistributedMinSources int     `yaml:"distributed_min_sources"`
	DistributedZ          float64 `yaml:"distributed_z"`
	DistributedWarmup     int     `yaml:"distributed_warmup_evals"`

	// Privilege change (T1548 elevation, T1098 account manipulation): an
	// (actor, action template) pair not seen during the learning period.
	PrivilegeLearnS int `yaml:"privilege_learn_s"`

	// Unusual access (T1078): a successful login from a source new to the
	// user, or at an hour the user never logs in.
	UnusualMinHistory     int `yaml:"unusual_min_history"`
	UnusualHourMinHistory int `yaml:"unusual_hour_min_history"`
	UnusualMinDays        int `yaml:"unusual_min_days"` // user history must span this long
	UnusualMaxSources     int `yaml:"unusual_max_sources_per_user"`

	CooldownS int `yaml:"cooldown_s"` // one alert per rule and key per cooldown
	MaxKeys   int `yaml:"max_keys"`   // per map per service; protects memory under attack
}

func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		Enabled:             true,
		BruteForceWindowS:   300,
		BruteForceThreshold: 10,
		SourceFailThreshold: 30,
		StuffingWindowS:     600, StuffingMinUsers: 20, StuffingMinFailureRatio: 0.8,
		DistributedWindowS: 3600, DistributedEvalS: 60, DistributedMinUsers: 30,
		DistributedMinSources: 20, DistributedZ: 5, DistributedWarmup: 60,
		PrivilegeLearnS:   86400,
		UnusualMinHistory: 10, UnusualHourMinHistory: 20, UnusualMinDays: 7, UnusualMaxSources: 64,
		CooldownS: 900, MaxKeys: 100_000,
	}
}

// ── classification ────────────────────────────────────────────────────

type authKind uint8

const (
	authNone authKind = iota
	authFailure
	authSuccess
	authElevation     // sudo / su / pkexec
	authAccountChange // role grants, group membership, new accounts
)

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// classify decides what an auth-related message is. It works on the
// message, not the Drain template: "Login failed user=<USER>" and "Login
// succeeded user=<USER>" have the same shape and Drain may merge them into
// "Login <*> user=<USER>". Each sshd attempt is counted once, on its
// "Failed ..."/"Accepted ..." line; the PAM, "Invalid user" and
// input_userauth lines that sshd logs for the same attempt are ignored.
func classify(lower string) authKind {
	switch {
	case containsAny(lower, "pam_unix(sshd", "input_userauth_request"):
		return authNone
	case containsAny(lower, "failed password for", "failed publickey for", "failed none for",
		"failed keyboard-interactive", "login failed", "login failure", "failed login",
		"authentication failed", "invalid credentials", "invalid password", "bad password", "auth failed"):
		return authFailure
	case containsAny(lower, "accepted password for", "accepted publickey for", "accepted keyboard-interactive",
		"login succeeded", "login successful", "logged in successfully", "successful login", "authentication succeeded"):
		return authSuccess
	case (strings.Contains(lower, "sudo:") && strings.Contains(lower, "command=")) ||
		containsAny(lower, "su: (to ", "pkexec", "elevated to") ||
		(strings.Contains(lower, "pam_unix(su") && strings.Contains(lower, "session opened")):
		return authElevation
	case (strings.Contains(lower, "role") && containsAny(lower, "granted", "assigned")) ||
		containsAny(lower, "added to group", "added to the admin", "group membership changed", "usermod", "useradd", "new user:",
			"promoted to", "permission granted", "granted admin", "authorized_keys"):
		return authAccountChange
	}
	return authNone
}

// identity pulls the (tokenized) user and source out of an event: the
// first usr_ and ip_ tokens in the message, else well-known attributes.
// Security rules never see raw usernames or addresses.
func identity(ev *event.Event) (user, source string) {
	user, source = firstToken(ev.Message, "usr_"), firstToken(ev.Message, "ip_")
	if user == "" {
		user = systemUser(ev.Message)
	}
	if user == "" {
		for _, k := range []string{"enduser.id", "user", "username", "user.name", "user_name"} {
			if v := ev.Attrs[k]; strings.HasPrefix(v, "usr_") {
				user = v
				break
			}
		}
	}
	if source == "" {
		for _, k := range []string{"client.address", "source.address", "net.peer.ip", "client_ip", "src_ip", "rhost", "remote_addr"} {
			if v := ev.Attrs[k]; strings.HasPrefix(v, "ip_") {
				source = v
				break
			}
		}
	}
	return user, source
}

// systemUser finds a readable system account (root, admin, ...) in the
// positions a username takes: "for [invalid user] X from", "user=X".
// Personal names never appear here in clear: redaction tokenized them.
func systemUser(msg string) string {
	for _, marker := range []string{"invalid user ", " for ", "user="} {
		i := strings.Index(msg, marker)
		if i < 0 {
			continue
		}
		rest := msg[i+len(marker):]
		end := strings.IndexAny(rest, " ;,")
		if end < 0 {
			end = len(rest)
		}
		if w := rest[:end]; redact.IsSystemAccount(w) {
			return strings.ToLower(w)
		}
	}
	return ""
}

func firstToken(s, prefix string) string {
	for i := 0; ; {
		k := strings.Index(s[i:], prefix)
		if k < 0 {
			return ""
		}
		k += i
		end := k + len(prefix) + 12
		if (k == 0 || !isWordChar(s[k-1])) && end <= len(s) && isHexStr(s[k+len(prefix):end]) &&
			(end == len(s) || !isWordChar(s[end])) {
			return s[k:end]
		}
		i = k + 1
	}
}

func isWordChar(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isHexStr(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ── per-service state ─────────────────────────────────────────────────

type timedSeq struct {
	ns  int64
	seq uint64
}

type srcStats struct {
	users     map[string]int64 // failing user -> last failure (arrival ns)
	fails     []int64          // failure times in the window
	successes []int64
}

type userHistory struct {
	first   int64 // event time of the earliest successful login seen
	n       int
	sources map[string]bool
	hours   [24]int
}

// Security is the security-rule state for one service. Like the rest of a
// shard's state it is owned by one goroutine.
type Security struct {
	cfg     SecurityConfig
	service string
	allowed map[string]bool

	bf        map[string][]timedSeq // user|source -> recent failures
	bySrc     map[string]*srcStats
	distUsers map[string]int64 // service-wide failing users -> last failure
	distSrcs  map[string]int64
	distBase  Baseline
	distFirst int64 // first failure seen (full windows only after this + window)
	distOpen  bool  // an incident is open: no new alert until the count is back near baseline

	firstSeen   int64
	knownPriv   map[string]bool // actor|template
	users       map[string]*userHistory
	cooldown    map[string]int64
	notAuth     map[int]bool // templates that cannot be auth-related (see Observe)
	KeysDropped int64
}

// NewSecurity creates the rules for one service. allowedTokens are the
// tokenized forms of SecurityConfig.AllowedSources.
func NewSecurity(cfg SecurityConfig, service string, allowedTokens map[string]bool) *Security {
	return &Security{
		cfg: cfg, service: service, allowed: allowedTokens,
		bf: map[string][]timedSeq{}, bySrc: map[string]*srcStats{},
		distUsers: map[string]int64{}, distSrcs: map[string]int64{},
		distBase: Baseline{Alpha: 0.05, WarmupTicks: cfg.DistributedWarmup, SigmaMin: 1, MaxUpdateZ: 2,
			NoiseFloor: func(mu float64, _ int) float64 { return math.Sqrt(max(mu, 0)) }}, // Poisson noise on a count
		knownPriv: map[string]bool{}, users: map[string]*userHistory{}, cooldown: map[string]int64{},
		notAuth: map[int]bool{},
	}
}

func secs(s int) int64 { return int64(s) * int64(time.Second) }

// authHints are words every auth-related template contains as constant
// tokens.
var authHints = []string{"fail", "accept", "login", "logged in", "succe", "authentic", "credential", "password",
	"sudo", "su:", "pkexec", "elevat", "role", "group", "usermod", "useradd", "new user", "promot", "permission",
	"authorized_keys", "invalid"}

// Observe applies the rules to one event. templateID/templateText are the
// event's Drain template in this service; templateChanged is true when this
// event generalised the template.
//
// Most events are not auth-related, so a template with none of the auth
// words and no <*> wildcard is remembered as "not auth" and its events skip
// classification. A wildcard could be hiding a word that varies ("Login
// <*>" merging failed/succeeded), so those templates are never cached, and
// a template that changes is re-examined.
func (s *Security) Observe(ev *event.Event, templateID int, templateText string, templateChanged bool) []Alert {
	if templateChanged {
		delete(s.notAuth, templateID)
	}
	if s.notAuth[templateID] {
		return nil
	}
	if templateText != "" && !strings.Contains(templateText, "<*>") {
		if lt := strings.ToLower(templateText); !containsAny(lt, authHints...) {
			if len(s.notAuth) < s.cfg.MaxKeys {
				s.notAuth[templateID] = true
			}
			return nil
		}
	}
	kind := classify(strings.ToLower(ev.Message))
	if kind == authNone {
		return nil
	}
	now := ev.ReceivedAt
	if s.firstSeen == 0 {
		s.firstSeen = now
	}
	user, src := identity(ev)
	var out []Alert
	switch kind {
	case authFailure:
		out = s.failure(ev, user, src, now, out)
	case authSuccess:
		out = s.success(ev, user, src, now, out)
	case authElevation, authAccountChange:
		out = s.privilege(ev, kind, user, templateID, templateText, now, out)
	}
	return out
}

func (s *Security) room(n int) bool {
	if n >= s.cfg.MaxKeys {
		s.KeysDropped++
		return false
	}
	return true
}

func (s *Security) failure(ev *event.Event, user, src string, now int64, out []Alert) []Alert {
	cfg := s.cfg
	// Brute force: one user, one source.
	if user != "" || src != "" {
		key := user + "|" + src
		series, ok := s.bf[key]
		if ok || s.room(len(s.bf)) {
			series = pruneSeq(append(series, timedSeq{now, ev.Seq}), now-secs(cfg.BruteForceWindowS))
			if len(series) > 4*cfg.BruteForceThreshold {
				series = series[len(series)-4*cfg.BruteForceThreshold:]
			}
			s.bf[key] = series
			if len(series) >= cfg.BruteForceThreshold {
				out = s.emit(out, SignalBruteForce, SevHigh, key, user, src, now, cfg.BruteForceWindowS,
					float64(len(series)), float64(cfg.BruteForceThreshold), seqsOf(series),
					[]string{"T1110.001"},
					fmt.Sprintf("%d failed logins for one user from one source in %d s", len(series), cfg.BruteForceWindowS))
			}
		}
	}
	if src == "" {
		return out
	}
	// Credential stuffing, single source.
	st, ok := s.bySrc[src]
	if !ok {
		if !s.room(len(s.bySrc)) {
			return out
		}
		st = &srcStats{users: map[string]int64{}}
		s.bySrc[src] = st
	}
	cut := now - secs(cfg.StuffingWindowS)
	st.fails = pruneTimes(append(st.fails, now), cut)
	st.successes = pruneTimes(st.successes, cut)
	if user != "" && (len(st.users) < cfg.MaxKeys) {
		st.users[user] = now
	}
	distinct := 0
	for _, t := range st.users {
		if t > cut {
			distinct++
		}
	}
	ratio := float64(len(st.fails)) / float64(len(st.fails)+len(st.successes))
	recent, bfCut := 0, now-secs(cfg.BruteForceWindowS)
	for i := len(st.fails) - 1; i >= 0 && st.fails[i] > bfCut; i-- {
		recent++
	}
	if recent >= cfg.SourceFailThreshold && ratio >= cfg.StuffingMinFailureRatio && !s.allowed[src] {
		out = s.emit(out, SignalBruteForce, SevHigh, "src|"+src, "", src, now, cfg.BruteForceWindowS,
			float64(recent), float64(cfg.SourceFailThreshold), []uint64{ev.Seq}, []string{"T1110"},
			fmt.Sprintf("%d failed logins from one source across %d accounts in %d s", recent, distinct, cfg.BruteForceWindowS))
	}
	if distinct >= cfg.StuffingMinUsers && ratio >= cfg.StuffingMinFailureRatio && !s.allowed[src] {
		out = s.emit(out, SignalCredentialStuffing, SevHigh, "src|"+src, "", src, now, cfg.StuffingWindowS,
			float64(distinct), float64(cfg.StuffingMinUsers), []uint64{ev.Seq}, []string{"T1110.004"},
			fmt.Sprintf("%d distinct usernames failed from one source in %d s (%.0f%% of its logins failed)", distinct, cfg.StuffingWindowS, ratio*100))
	}
	// Distributed stuffing: counted service-wide, evaluated on ticks.
	if user != "" && s.room(len(s.distUsers)) {
		s.distUsers[user] = now
	}
	if s.room(len(s.distSrcs)) {
		s.distSrcs[src] = now
	}
	if s.distFirst == 0 {
		s.distFirst = now
	}
	return out
}

func (s *Security) success(ev *event.Event, user, src string, now int64, out []Alert) []Alert {
	cfg := s.cfg
	if src != "" {
		if st, ok := s.bySrc[src]; ok {
			st.successes = append(st.successes, now)
		}
	}
	// A success right after a brute-force run is the attack working.
	if series, ok := s.bf[user+"|"+src]; ok {
		series = pruneSeq(series, now-secs(cfg.BruteForceWindowS))
		if len(series) >= cfg.BruteForceThreshold/2 && len(series) > 0 {
			out = s.emit(out, SignalBruteForce, SevCritical, "success|"+user+"|"+src, user, src, now, cfg.BruteForceWindowS,
				float64(len(series)), float64(cfg.BruteForceThreshold), append(seqsOf(series), ev.Seq),
				[]string{"T1110.001", "T1078"},
				fmt.Sprintf("successful login after %d failures for the same user and source", len(series)))
		}
		delete(s.bf, user+"|"+src)
	}
	if user == "" || src == "" {
		return out
	}
	// Unusual access: compare with this user's history, then learn.
	h, ok := s.users[user]
	if !ok {
		if !s.room(len(s.users)) {
			return out
		}
		h = &userHistory{first: ev.Timestamp, sources: map[string]bool{}}
		s.users[user] = h
	}
	hour := time.Unix(0, ev.Timestamp).UTC().Hour()
	// Judge only users whose habits we have watched long enough: logins
	// alone are not enough, because a second home address or the office
	// NAT may simply not have shown up yet.
	// Habits are about when the user logged in, so maturity uses event time
	// (like the hour-of-day check), not when TREMOR received the lines.
	h.first = min(h.first, ev.Timestamp)
	mature := ev.Timestamp-h.first >= secs(cfg.UnusualMinDays*86400)
	newSource := mature && h.n >= cfg.UnusualMinHistory && !h.sources[src] && len(h.sources) < cfg.UnusualMaxSources
	oddHour := mature && h.n >= cfg.UnusualHourMinHistory && h.hours[hour] == 0 && h.hours[(hour+23)%24] == 0 && h.hours[(hour+1)%24] == 0
	if newSource || oddHour {
		// One weak signal is INFO (people travel, change ISPs, work late):
		// it is recorded and shown, not paged. Both together is the classic
		// account-takeover shape and pages.
		sev, why := SevInfo, ""
		switch {
		case newSource && oddHour:
			sev, why = SevHigh, fmt.Sprintf("login from a source this user never used, at %02d:00 UTC when they never log in", hour)
		case newSource:
			why = fmt.Sprintf("login from a source this user never used (%d previous logins from %d sources)", h.n, len(h.sources))
		default:
			why = fmt.Sprintf("login at %02d:00 UTC, an hour this user never logs in (%d previous logins)", hour, h.n)
		}
		out = s.emit(out, SignalUnusualAccess, sev, "access|"+user+"|"+src, user, src, now, 0,
			float64(h.n), float64(cfg.UnusualMinHistory), []uint64{ev.Seq}, []string{"T1078"}, why)
	}
	h.n++
	if len(h.sources) < cfg.UnusualMaxSources {
		h.sources[src] = true
	}
	h.hours[hour]++
	return out
}

// privilege: the baseline key is (actor, action template, privileged?).
// The actor is whoever comes after " by " ("Role admin granted to user=X by
// admin Y" is Y's action), else the first user in the line (sudo's caller).
// "privileged" looks only at the action text before " by ": Drain merges
// "Role viewer granted" and "Role admin granted" into one template, so a
// role admin who only ever granted viewer would otherwise grant admin
// unnoticed.
func (s *Security) privilege(ev *event.Event, kind authKind, user string, templateID int, templateText string, now int64, out []Alert) []Alert {
	lower := strings.ToLower(ev.Message)
	action := lower
	if i := strings.Index(lower, " by "); i >= 0 {
		action = lower[:i]
		if t := firstToken(ev.Message[i:], "usr_"); t != "" {
			user = t
		}
	}
	privileged := containsAny(action, "root", "admin", "wheel", "superuser", "sudo")
	key := fmt.Sprintf("%s|%d|%t", user, templateID, privileged)
	if s.knownPriv[key] {
		return out
	}
	if now-s.firstSeen < secs(s.cfg.PrivilegeLearnS) {
		if s.room(len(s.knownPriv)) {
			s.knownPriv[key] = true // learning: this is part of the service's baseline
		}
		return out
	}
	// The baseline is frozen after learning: a repeat of the same
	// out-of-baseline action days later alerts again (the cooldown stops
	// floods). Accepting new normal behaviour is an analyst decision, not
	// something the detector should learn on its own from possibly
	// malicious activity.
	tech, what := []string{"T1548"}, "privilege elevation"
	if kind == authAccountChange {
		tech, what = []string{"T1098"}, "account or role change"
	} else if strings.Contains(strings.ToLower(ev.Message), "sudo") {
		tech = []string{"T1548.003"}
	}
	sev := SevWarning
	if privileged {
		sev = SevHigh
	}
	return s.emit(out, SignalPrivilegeChange, sev, "priv|"+key, user, "", now, 0, 1, 0, []uint64{ev.Seq}, tech,
		fmt.Sprintf("%s not seen for this user during the %s baseline: %q", what, time.Duration(secs(s.cfg.PrivilegeLearnS)), templateText))
}

// Tick prunes state and evaluates the distributed stuffing rule. k is the
// tick (unix seconds).
func (s *Security) Tick(k int64) []Alert {
	cfg := s.cfg
	if cfg.DistributedEvalS <= 0 || k%int64(cfg.DistributedEvalS) != 0 {
		return nil
	}
	now := k * int64(time.Second)
	// Housekeeping.
	for key, series := range s.bf {
		if series = pruneSeq(series, now-secs(cfg.BruteForceWindowS)); len(series) == 0 {
			delete(s.bf, key)
		} else {
			s.bf[key] = series
		}
	}
	for src, st := range s.bySrc {
		cut := now - secs(cfg.StuffingWindowS)
		for u, t := range st.users {
			if t <= cut {
				delete(st.users, u)
			}
		}
		st.fails, st.successes = pruneTimes(st.fails, cut), pruneTimes(st.successes, cut)
		if len(st.users) == 0 && len(st.fails) == 0 && len(st.successes) == 0 {
			delete(s.bySrc, src)
		}
	}
	for key, t := range s.cooldown {
		if now-t > secs(cfg.CooldownS) {
			delete(s.cooldown, key)
		}
	}
	// Distributed stuffing over the last DistributedWindowS.
	cut := now - secs(cfg.DistributedWindowS)
	for u, t := range s.distUsers {
		if t <= cut {
			delete(s.distUsers, u)
		}
	}
	for src, t := range s.distSrcs {
		if t <= cut {
			delete(s.distSrcs, src)
		}
	}
	if s.distFirst == 0 || now-s.distFirst < secs(cfg.DistributedWindowS) {
		return nil // only judge full windows
	}
	x := float64(len(s.distUsers))
	if !s.distBase.Seeded() {
		s.distBase.AddWarmup(x)
		return nil
	}
	z := s.distBase.Z(x, 0)
	mu, _ := s.distBase.Mu()
	var out []Alert
	firing := z >= cfg.DistributedZ && len(s.distUsers) >= cfg.DistributedMinUsers && len(s.distSrcs) >= cfg.DistributedMinSources
	switch {
	case s.distOpen && z < 2:
		// The attack's failures have aged out of the window: re-arm. Until
		// then the decaying tail of one attack must not page again.
		s.distOpen = false
	case firing && !s.distOpen:
		s.distOpen = true
		delete(s.cooldown, string(SignalCredentialStuffing)+"|distributed")
		out = s.emit(out, SignalCredentialStuffing, SevHigh, "distributed", "", "", now, cfg.DistributedWindowS,
			x, mu, nil, []string{"T1110.004"},
			fmt.Sprintf("%d distinct usernames failed from %d sources in %d s (baseline %.1f, z=%.1f)", len(s.distUsers), len(s.distSrcs), cfg.DistributedWindowS, mu, z))
	}
	s.distBase.Update(x, z, s.distOpen) // never learn from an attack in progress
	return out
}

// emit builds an alert unless the same rule fired for the same key within
// the cooldown.
func (s *Security) emit(out []Alert, t SignalType, sev Severity, key, user, src string, now int64, windowS int,
	value, baseline float64, seqs []uint64, tech []string, reason string) []Alert {
	ck := string(t) + "|" + key
	if last, ok := s.cooldown[ck]; ok && now-last < secs(s.cfg.CooldownS) {
		return out
	}
	s.cooldown[ck] = now
	k := now / int64(time.Second)
	ik := incidentKey{t, s.service, key}
	a := Alert{
		ID: alertID(incidentID(ik, k), StatusOpen, k), IncidentID: incidentID(ik, k),
		Type: t, Status: StatusOpen, Severity: sev.String(), Service: s.service,
		Value: f64(value), Baseline: f64(baseline), Reason: reason,
		WindowStart: k - int64(windowS), WindowEnd: k, CreatedAt: k, UpdatedAt: k,
		Techniques: tech, User: user, Source: src,
	}
	if len(seqs) > 0 {
		a.SourceSeqs = SeqRange{First: minU(seqs), Last: maxU(seqs), ErrorSeqs: lastN(seqs, 16)}
	}
	return append(out, a)
}

func pruneSeq(xs []timedSeq, cut int64) []timedSeq {
	i := 0
	for i < len(xs) && xs[i].ns <= cut {
		i++
	}
	return xs[i:]
}

func pruneTimes(xs []int64, cut int64) []int64 {
	i := 0
	for i < len(xs) && xs[i] <= cut {
		i++
	}
	return xs[i:]
}

func seqsOf(xs []timedSeq) []uint64 {
	out := make([]uint64, 0, len(xs))
	for _, x := range xs {
		out = append(out, x.seq)
	}
	return out
}

func minU(xs []uint64) uint64 {
	m := xs[0]
	for _, x := range xs {
		m = min(m, x)
	}
	return m
}

func maxU(xs []uint64) uint64 {
	m := xs[0]
	for _, x := range xs {
		m = max(m, x)
	}
	return m
}

func lastN(xs []uint64, n int) []uint64 {
	if len(xs) > n {
		xs = xs[len(xs)-n:]
	}
	return append([]uint64(nil), xs...)
}

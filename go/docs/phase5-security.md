# Phase 5: security detection

## Results

| Measured | All severities | Paging (WARNING+) |
|---|---|---|
| Detection, brute force (10 attacks) | 10/10 | 10/10 |
| Detection, credential stuffing (10 single-source + 5 distributed) | 15/15 | 15/15 |
| Detection, privilege change (10) | 10/10 | 10/10 |
| Detection, unusual access (10) | 10/10 | 5/10: account takeovers 3/3; single-signal anomalies are INFO by design |
| **False alarms, 504 h of attack-free traffic** | 163 (0.32/h), all UNUSUAL_ACCESS INFO | **0** |
| Same traffic with the NAT guards switched off | +16 CREDENTIAL_STUFFING HIGH | **16 (0.032/h)** |
| Alerts unrelated to any attack, during the 504 h attack run | 168 (unusual-access INFO) | **0** |
| Live run (real server, loadgen `-attack all`) | 4/4 attack types alerted within 0–19 s, ATT&CK-tagged, tokenized identities, 0 raw usernames in logs | |
| Loghub OpenSSH 2k (real sshd logs, no labels) | all 6 IPs with ≥10 failures/5 min got an alert (heuristic cross-check, not ground truth) | |

Sources:

- `bench/results/phase5/security-eval.md` (`go run ./cmd/eval -security`)
- `live-attacks-*.json(l)` (`bench/live_attacks.sh`)
- `loghub-openssh-2k.md` (`go run ./cmd/eval -ssh bench/data/OpenSSH_2k.log`)

**Read the simulated numbers as what they are.** I wrote both the attack simulator and the rules. 100% on a simulator only means the rules catch the attack shapes the simulator produces. What the evaluation *does* show is:

- the false-alarm behaviour on a deliberately hard background (a busy office NAT with a weekly password-rotation day, employees roaming to new IPs);
- that the NAT guards measurably matter (0 → 16 pages when removed);
- that real sshd attack traffic (Loghub) is caught.

## Rules

All rules run inside the shard that owns a service (single goroutine, no locks), on events that redaction has already processed. They see only `usr_<hmac>` and `ip_<hmac>` tokens, plus a short list of role accounts such as `root` and `admin` (see "System accounts" below). Each alert carries MITRE ATT&CK IDs, the tokenized user and source, the observed value vs the threshold or baseline, the window, and the WAL sequence numbers of the evidence.

| Rule | Signal | ATT&CK | Default | Why this default |
|---|---|---|---|---|
| Brute force, per (user, source) | ≥10 failures for one user from one source in 5 min | T1110.001 | 10 / 300 s | A person who has forgotten a password gives up or resets after 3–5 tries. 10 in 5 minutes is beyond human, and still fires inside about a minute for automated guessing (median delay in the simulation: 48 s). |
| Brute force → success | a success for the same (user, source) after ≥5 recent failures | T1110.001 + T1078 | CRITICAL | The attack worked. This is the alert that matters most. |
| Brute force, per source | ≥30 failures from one source in 5 min, any accounts, ≥80% failing | T1110 | 30 / 300 s | Catches SSH dictionary runs (admin, root, test, pi, …) that stay under both other thresholds. This gap was found on Loghub data (below). One attempt every 10 s for 5 minutes is not a person. |
| Credential stuffing, single source | ≥20 distinct usernames failing from one source in 10 min **and** ≥80% of that source's attempts failing | T1110.004 | 20 / 600 s / 0.8 | Stuffing tries each leaked credential once, so the signal is *breadth* (distinct users), not depth. The ratio guard is the NAT defence (below). |
| Credential stuffing, distributed ("low and slow") | distinct failing usernames per hour ≥5σ above the service's learned baseline, ≥30 users, from ≥20 sources | T1110.004 | 3600 s, z ≥ 5 | Each source stays under every per-source threshold, so only the service-wide breadth gives it away. It uses the same EWMA baseline machinery as Phase 3, with a Poisson (√μ) noise floor because it's a count. The incident stays open until z < 2, so the hour-long tail of one attack doesn't page again every cooldown (a bug the evaluation caught). |
| Privilege change | an (actor, action template, privileged?) never seen during the learning period: sudo/su/pkexec (**T1548**, T1548.003 for sudo) or role/group/account changes (**T1098**) | T1548, T1098 | learn 24 h, then freeze | "Outside the service's baseline" literally: learn who does what for a day, then any new actor/action pair is suspicious. The baseline is **frozen**: the detector never learns from post-baseline activity that might be malicious. Accepting new normal behaviour is an analyst action (the API arrives in Phase 6). |
| Unusual access | a success from a source this user never used, or at an hour (±1) they never log in | T1078 | history ≥ 7 days and ≥10 (source) / ≥20 (hour) logins | A login count alone isn't enough history: a second home address may not have shown up yet (the first evaluation had 100+ false alarms because of exactly this). One signal alone is **INFO**; both together (the classic account-takeover shape) is **HIGH**. |

**Cooldown.** One alert per rule and key per 15 minutes. A 40-attempt brute force is one alert, not four.

**Memory.** Every per-key map is capped (`max_keys`, 100k per service), with old entries pruned every minute, so an attacker spraying random usernames can't exhaust memory.

### Classification: per message, not per template

The classifier decides failure / success / elevation / account change from keywords in the (redacted) message.

- **Why not per template:** Drain can merge `Login failed user=<USER> ip=<IP>` and `Login succeeded user=<USER> ip=<IP>` (75% token similarity, above `sim_th`) into `Login <*> user=…`.
- **Where templates are used:** as the action identity in the privilege baseline, and as a fast path. A template with no auth keyword and no `<*>` is remembered as "not auth", so most events skip classification: **3 ns instead of 1,045 ns** per event (`bench/results/phase5/microbench.txt`). The cache entry is dropped whenever Drain generalises that template.
- **Each sshd attempt counts once.** sshd logs one failed attempt as 2–4 lines (`Invalid user`, `input_userauth_request`, `pam_unix(sshd:auth): authentication failure`, `Failed password`). Only the `Failed …`/`Accepted …` line counts, or brute-force thresholds would effectively be 3–4× lower.

### System accounts stay readable

`root`, `admin`, `ubuntu`, `postgres`, … identify no natural person, so they aren't personal data, and they're exactly what attackers target. The redactor keeps a fixed list of them readable, which is why alerts say `user=root` instead of an opaque token.

This changed the Phase 4 test set's definition of "username PII". The regenerated set gives recall 100%, **precision 94.9%** (was 94.5%) and 0 leaks over 4,734 labelled values. Working on Phase 5 also found and fixed three Phase 4 redaction gaps:

- the sudo actor (`sudo:   bob : …`) wasn't tokenized;
- `/home/<name>` leaked the username;
- `PWD=` (sudo's working directory) was being masked as a password.

## How to avoid flagging a busy NAT gateway as credential stuffing

A corporate NAT, a university, a mobile carrier's CGNAT or a cloud egress puts hundreds of real users behind one IP. On a normal Monday at 09:00 the office NAT in the simulation sends 400 logins in 30 minutes; with 6% typos that's ~24 distinct users failing from one address. On password-rotation day the typo rate is 25%, so about 100 distinct users fail within the hour. A rule that only counts "distinct usernames failing from one source" pages on every rotation day.

What separates the NAT from an attacker:

1. **Failure ratio (implemented).** An attacker's credentials are mostly wrong, so ≥80% of its attempts fail. The NAT's users mostly *succeed*: even on rotation day about 20% of attempts fail, and most of those users retry and get in. Requiring `failures / attempts ≥ 0.8` from the source removes the NAT without losing attackers. That includes the 2% of leaked credentials that work, since 98% failing is still far above 0.8.
2. **Source spread for the distributed rule (implemented).** The low-and-slow rule needs the failing users to come from ≥20 different sources. A NAT spike, however large, comes from one.
3. **Allowlist (implemented, as a last resort).** `detect.security.allowed_sources` takes raw IPs of known egress points. They're tokenized with the HMAC key at startup, so the allowlist itself never stores an address alongside events. It exempts only the single-source rules: a compromised internal host behind the NAT is still visible to brute-force-per-user and to the distributed rule.
4. **What I did not do:** raise thresholds until the NAT goes quiet. That would hide real stuffing from small attackers too.

**Measured:** the same 504 h of attack-free traffic gives 0 paging alerts with the guards on, and **16 false HIGH credential-stuffing pages** with the failure-ratio and min-sources guards off.

**Remaining risks:**

- An attacker who mixes in valid logins to keep its failure ratio under 80% won't trip the single-source rule. It will still trip the distributed rule if it spreads across sources, and the per-user brute force if it focuses.
- A NAT where most logins really fail (a broken SSO rollout) will page, and arguably should.

## Loghub OpenSSH replay

`go run ./cmd/eval -ssh bench/data/OpenSSH_2k.log` runs the real public dataset through the same pipeline (redaction → Drain → rules). Results: 2,000 lines, 4 h 9 min of log, 8 brute-force alerts and 1 credential-stuffing alert. Examples:

- `BRUTE_FORCE user=root`: 10 failed logins for one user from one source in 300 s;
- `BRUTE_FORCE user=admin`;
- `CREDENTIAL_STUFFING`: 20 distinct usernames failed from one source in 600 s (100% of its logins failed).

The dataset has **no attack labels**. As a heuristic cross-check, I count independently from the raw text which IPs have ≥10 failed attempts inside any 5-minute window; TREMOR alerted on **all 6**.

The replay also found a real gap in the first rule set. `103.99.0.122` made 46 failed attempts in about 3 minutes across 19 default accounts (`admin`, `root`, `user`, `ubnt`, `cisco`, `pi`, `PlcmSpIp`, …). That's at most 7 per account, one distinct user short of the stuffing threshold. The per-source brute-force rule exists because of this. Its threshold (30 in 5 min) was set from "faster than any human", not fitted to this IP (which made 46).

The 2k file is a sample. The full Loghub SSH log (~655k lines) can go in `bench/data/SSH.log` and be replayed the same way.

**Live replay:** `loadgen -replay-ssh bench/data/OpenSSH_2k.log -speed 60` sends it to a running server, paced at 60× log time. Rule windows use arrival time, so compressing time makes attacks look denser than they were. The offline replay is the faithful one.

## Attack simulator

**Offline evaluation (`internal/sim`).** A deterministic 21-day scenario:

- 600 employees with 1–2 home IPs and per-person work hours, 10% on night shift, and 400 behind one office NAT;
- 4% typo-then-success logins;
- occasional logins from brand-new IPs (travel, new ISP);
- admins with daily publickey SSH and sudo;
- three admins doing routine role grants.

Attacks start after 14 days of learning, and each is labelled with type, variant, service, time window and the raw user and source. The evaluator tokenizes those with the same key the redactor uses.

**Live (`cmd/loadgen -attack all|brute_force|…`).** Injects each attack into normal loadgen traffic against a running server and writes the ground truth to the summary JSON.

- The unusual-access attack sends a prelude of 30 past logins carrying their real (past) timestamps. History maturity uses event time, so the server sees a 10-day habit immediately.
- The privilege attack needs the server's learning period to have elapsed, so `bench/live_attacks.sh` runs the server with `privilege_learn_s: 20`.

## Limitations

- **State is per service.** A source attacking two services shows up as two smaller patterns; the Phase 6 correlator joins alerts across services. State is also in memory: after a restart, user histories, privilege baselines and the distributed baseline relearn (the same trade-off as Phase 3).
- **Classification is keyword-based** (English sshd/PAM/sudo/app phrasing). A product with different wording needs entries in `classify` or structured attributes (`event.outcome`-style). The rules already read identity from `enduser.id` / `client.address` attributes when the message has none.
- **Hour-of-day uses UTC event time.** A user who travels across time zones looks "unusual" at INFO, which is one reason single-signal anomalies don't page.
- **Redaction gap:** free text with no keyword, like "User bob added to group wheel", isn't tokenized; structured `user=`/`by admin` forms are. The simulator uses the structured form.

## Reproduce

```bash
go run ./cmd/eval -security
go run ./cmd/eval -ssh bench/data/OpenSSH_2k.log
bench/live_attacks.sh
go test ./internal/detect/ ./internal/eval/
```

The first command runs the simulator evaluation (about 10 s). The second replays the Loghub sample; download it with `curl -o bench/data/OpenSSH_2k.log https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log`. The third is the live server with every attack injected. The fourth runs the rule unit tests and the acceptance test.

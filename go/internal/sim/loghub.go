package sim

import (
	"bufio"
	"io"
	"strings"
	"time"
)

// ParseSyslog parses a Loghub OpenSSH line:
//
//	Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
//
// Syslog timestamps have no year; the caller supplies one. The message
// keeps its "sshd[pid]: " prefix, as the simulator's sshd lines do.
func ParseSyslog(line string, year int) (Line, bool) {
	if len(line) < 16 {
		return Line{}, false
	}
	ts, err := time.Parse("Jan _2 15:04:05", line[:15])
	if err != nil {
		return Line{}, false
	}
	ts = ts.AddDate(year-ts.Year(), 0, 0)
	rest := strings.TrimLeft(line[15:], " ")
	sp := strings.IndexByte(rest, ' ') // skip the host name
	if sp < 0 {
		return Line{}, false
	}
	msg := strings.TrimSpace(rest[sp+1:])
	service := "sshd"
	if i := strings.IndexAny(msg, "[:"); i > 0 {
		service = msg[:i]
	}
	return Line{TS: ts, Service: service, Level: "INFO", Message: msg}, true
}

// ReadSyslog parses every line of r, skipping lines it cannot parse.
// Timestamps that go backwards (a new year in the file) are kept as-is.
func ReadSyslog(r io.Reader, year int) (lines []Line, skipped int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if l, ok := ParseSyslog(sc.Text(), year); ok {
			lines = append(lines, l)
		} else {
			skipped++
		}
	}
	return lines, skipped, sc.Err()
}

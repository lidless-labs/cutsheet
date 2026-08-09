package syslogtrigger

import (
	"regexp"
	"strings"
	"unicode"
)

// maxChangedByLen caps extracted usernames so a malformed message cannot
// inflate the stored attribution field.
const maxChangedByLen = 128

// Cisco-family CONFIG_I messages (IOS, IOS XE stackwise, IOS XR, EOS, NX-OS):
// "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (198.18.0.5)"
var ciscoConfigUser = regexp.MustCompile(
	`(?i)%(?:SYS-(?:SW\d+-)?5-CONFIG_I|MGBL-SYS-5-CONFIG_I|VSHD-5-VSHD_SYSLOG_CONFIG_I|SYS-5-CONFIG_I):\s+Configured from \S+ by (\S+)`)

// Junos UI_COMMIT: "UI_COMMIT: User 'alice' requested 'commit' operation ..."
var junosCommitUser = regexp.MustCompile(`UI_COMMIT:\s+User '([^']+)'`)

// ParseChangedBy extracts a device-local username from a syslog audit event.
// It returns "" when the message is not a recognized config-change audit
// event or carries no usable user — callers treat that as graceful
// degradation (still snapshot, leave attribution empty).
func ParseChangedBy(message string) string {
	if message == "" {
		return ""
	}
	if m := ciscoConfigUser.FindStringSubmatch(message); len(m) == 2 {
		return sanitizeChangedBy(m[1])
	}
	if m := junosCommitUser.FindStringSubmatch(message); len(m) == 2 {
		return sanitizeChangedBy(m[1])
	}
	return ""
}

func sanitizeChangedBy(user string) string {
	user = strings.TrimSpace(user)
	user = strings.Trim(user, `'"`)
	if user == "" {
		return ""
	}
	for _, r := range user {
		if unicode.IsControl(r) {
			return ""
		}
	}
	if len(user) > maxChangedByLen {
		user = user[:maxChangedByLen]
	}
	return user
}

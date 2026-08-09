package syslogtrigger

import "testing"

func TestParseChangedBy(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "ios CONFIG_I",
			msg:  `<189>May  9 12:00:00 router 12345: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (198.18.0.5)`,
			want: "admin",
		},
		{
			name: "ios stackwise CONFIG_I",
			msg:  `<189>May  9 12:00:00 router %SYS-SW1-5-CONFIG_I: Configured from console by dave on console`,
			want: "dave",
		},
		{
			name: "iosxr CONFIG_I",
			msg:  `<189>May  9 12:00:00 router %MGBL-SYS-5-CONFIG_I: Configured from console by xr-admin on vty0 (198.18.0.8)`,
			want: "xr-admin",
		},
		{
			name: "eos CONFIG_I",
			msg:  `<189>May  9 12:00:00 switch %SYS-5-CONFIG_I: Configured from console by charlie on vty1 (198.18.0.7)`,
			want: "charlie",
		},
		{
			name: "nxos CONFIG_I",
			msg:  `<189>May  9 12:00:00 switch %VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by bob on 198.18.0.6`,
			want: "bob",
		},
		{
			name: "junos UI_COMMIT",
			msg:  `<30>May  9 12:00:00 router mgd[1234]: UI_COMMIT: User 'alice' requested 'commit' operation (comment: none)`,
			want: "alice",
		},
		{
			name: "unrelated message degrades empty",
			msg:  `<189>May  9 12:00:00 router %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up`,
			want: "",
		},
		{
			name: "empty message",
			msg:  "",
			want: "",
		},
		{
			name: "generic trigger body without audit user",
			msg:  `<189>config changed`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseChangedBy(tt.msg)
			if got != tt.want {
				t.Fatalf("ParseChangedBy() = %q, want %q", got, tt.want)
			}
		})
	}
}

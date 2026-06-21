package respond

import "testing"

// fakeProc is an injectable procResolver: it returns canned procInfo by pid so
// unit tests never touch real /proc. The decision layer reading from it proves
// the gates work on identity facts WITHOUT any real process or any actuator.
type fakeProc map[int]procInfo

func (f fakeProc) resolve(pid int) procInfo {
	if info, ok := f[pid]; ok {
		info.Pid = pid
		return info
	}
	return procInfo{Pid: pid} // Live=false
}

func TestUnderStagingDir(t *testing.T) {
	staging := []string{"/tmp/", "/dev/shm/", "/var/tmp/"}
	cases := []struct {
		path string
		want bool
	}{
		{"/tmp/x/payload", true},
		{"/tmp/payload", true},
		{"/dev/shm/x", true},
		{"/var/tmp/y", true},
		{"/tmpfoo/x", false}, // segment boundary: /tmpfoo is NOT under /tmp
		{"/opt/app/server", false},
		{"/usr/bin/curl", false},
		{"/", false},
	}
	for _, tc := range cases {
		if got := underStagingDir(tc.path, staging); got != tc.want {
			t.Errorf("underStagingDir(%q)=%v want %v", tc.path, got, tc.want)
		}
	}
}

// A "/" staging dir must never make everything staging-resident.
func TestUnderStagingDirRejectsRootStaging(t *testing.T) {
	if underStagingDir("/opt/app", []string{"/"}) {
		t.Error("a '/' staging dir must not make /opt/app staging-resident")
	}
}

func TestIsProtectedExe(t *testing.T) {
	cases := []struct {
		name  string
		info  procInfo
		never []string
		want  bool
	}{
		{"pid1", procInfo{Pid: 1, Exe: "/tmp/x"}, nil, true},
		{"pid0", procInfo{Pid: 0, Exe: "/tmp/x"}, nil, true},
		{"sshd", procInfo{Pid: 100, Exe: "/usr/sbin/sshd"}, nil, true},
		{"agentd", procInfo{Pid: 100, Exe: "/usr/local/bin/agentd"}, nil, true},
		{"collector", procInfo{Pid: 100, Exe: "/usr/local/bin/collector"}, nil, true},
		{"login-shell-bash", procInfo{Pid: 100, Exe: "/bin/bash"}, nil, true},
		{"staging-dropper", procInfo{Pid: 100, Exe: "/tmp/x/payload"}, nil, false},
		{"never-list-exact", procInfo{Pid: 100, Exe: "/srv/app/bin"}, []string{"/srv/app/bin"}, true},
		{"never-list-prefix", procInfo{Pid: 100, Exe: "/opt/app/sub/bin"}, []string{"/opt/app"}, true},
		{"never-list-miss", procInfo{Pid: 100, Exe: "/opt/other/bin"}, []string{"/opt/app"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isProtectedExe(tc.info, tc.never); got != tc.want {
				t.Errorf("isProtectedExe(%+v, %v)=%v want %v", tc.info, tc.never, got, tc.want)
			}
		})
	}
}

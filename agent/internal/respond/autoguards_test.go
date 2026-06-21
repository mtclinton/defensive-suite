package respond

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

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

// procFn adapts a function to a procResolver, so a test can return a DIFFERENT
// procInfo on each call (e.g. a fresh /tmp name per exec for the dedup-storm test).
type procFn func(pid int) procInfo

func (f procFn) resolve(pid int) procInfo { return f(pid) }

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
	const selfExe = "/usr/local/bin/agentd"
	protected := defaultProtectedPaths
	cases := []struct {
		name      string
		info      procInfo
		self      string
		protected []string
		never     []string
		want      bool
	}{
		{"pid1", procInfo{Pid: 1, Exe: "/tmp/x"}, selfExe, protected, nil, true},
		{"pid0", procInfo{Pid: 0, Exe: "/tmp/x"}, selfExe, protected, nil, true},
		// Protection is anchored to the REAL system path, not the basename.
		{"sshd-real-path", procInfo{Pid: 100, Exe: "/usr/sbin/sshd"}, selfExe, protected, nil, true},
		{"agentd-self-exe", procInfo{Pid: 100, Exe: "/usr/local/bin/agentd"}, selfExe, protected, nil, true},
		{"collector-real-path", procInfo{Pid: 100, Exe: "/usr/local/bin/collector"}, selfExe, protected, nil, true},
		{"login-shell-real-path", procInfo{Pid: 100, Exe: "/bin/bash"}, selfExe, protected, nil, true},
		// FIX 4: a staging-resident dropper merely NAMED a protected basename is NOT
		// protected — basename matching was the auto-eligibility evasion bug.
		{"staging-named-bash", procInfo{Pid: 100, Exe: "/tmp/x/bash"}, selfExe, protected, nil, false},
		{"staging-named-sshd", procInfo{Pid: 100, Exe: "/dev/shm/sshd"}, selfExe, protected, nil, false},
		{"staging-named-agentd", procInfo{Pid: 100, Exe: "/tmp/.x/agentd"}, selfExe, protected, nil, false},
		{"staging-dropper", procInfo{Pid: 100, Exe: "/tmp/x/payload"}, selfExe, protected, nil, false},
		// self-exe protection holds even when agentd runs from a non-default path.
		{"self-exe-custom", procInfo{Pid: 100, Exe: "/opt/agentd/bin/agentd"}, "/opt/agentd/bin/agentd", protected, nil, true},
		{"self-exe-empty-not-protected", procInfo{Pid: 100, Exe: "/tmp/x/agentd"}, "", protected, nil, false},
		{"never-list-exact", procInfo{Pid: 100, Exe: "/srv/app/bin"}, selfExe, protected, []string{"/srv/app/bin"}, true},
		{"never-list-prefix", procInfo{Pid: 100, Exe: "/opt/app/sub/bin"}, selfExe, protected, []string{"/opt/app"}, true},
		{"never-list-miss", procInfo{Pid: 100, Exe: "/opt/other/bin"}, selfExe, protected, []string{"/opt/app"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isProtectedExe(tc.info, tc.self, tc.protected, tc.never); got != tc.want {
				t.Errorf("isProtectedExe(%+v, %q, …)=%v want %v", tc.info, tc.self, got, tc.want)
			}
		})
	}
}

func TestStripDeleted(t *testing.T) {
	cases := map[string]string{
		"/tmp/.x/payload (deleted)": "/tmp/.x/payload",
		"memfd:foo (deleted)":       "memfd:foo",
		"/usr/bin/curl":             "/usr/bin/curl",
		" /tmp/x (deleted) ":        "/tmp/x",
		"":                          "",
	}
	for in, want := range cases {
		if got := stripDeleted(in); got != want {
			t.Errorf("stripDeleted(%q)=%q want %q", in, got, want)
		}
	}
}

// writeFakeProc fabricates procRoot/<pid>/{exe→target, status, stat} so the REAL
// resolver's os.Readlink / deleted-marker / liveness path is exercised against a
// real (temp) /proc tree rather than an injected fake procResolver.
func writeFakeProc(t *testing.T, root string, pid int, target string, uid int, startTime uint64) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tpayload\nUid:\t" + strconv.Itoa(uid) + "\t" + strconv.Itoa(uid) + "\t" +
		strconv.Itoa(uid) + "\t" + strconv.Itoa(uid) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	// /proc/<pid>/stat: "<pid> (comm) S ..." with starttime at field 22 (index 19
	// post-comm). Pad fields 3..21 (19 fields) then the starttime.
	fields := make([]string, 0, 21)
	fields = append(fields, "S") // field 3 (state)
	for i := 4; i <= 21; i++ {
		fields = append(fields, "0")
	}
	fields = append(fields, strconv.FormatUint(startTime, 10)) // field 22 (starttime)
	stat := strconv.Itoa(pid) + " (payload) " + joinSpace(fields) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
}

func joinSpace(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out
}

// FIX 1: the REAL resolver must resolve a FILELESS (deleted/memfd) exe to its
// stripped staging path AND report Live=true (the process still exists even
// though its image is gone). Before the fix, EvalSymlinks(/proc/<pid>/exe)
// returned an error for a deleted target → Live=false → ZERO quarantine
// candidates → a falsely-clean FP soak.
func TestRealResolverFilelessExeIsLive(t *testing.T) {
	root := t.TempDir()
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()

	// (a) deleted on-disk image: target ends in " (deleted)".
	writeFakeProc(t, root, 1001, "/tmp/.x/payload (deleted)", 1000, 5000)
	if got := (realProcResolver{}).resolve(1001); !got.Live || got.Exe != "/tmp/.x/payload" || got.UID != 1000 || got.StartTime != 5000 {
		t.Errorf("deleted exe: got %+v; want Live, Exe=/tmp/.x/payload, UID=1000, StartTime=5000", got)
	}

	// (b) memfd image: target "memfd:foo (deleted)".
	writeFakeProc(t, root, 1002, "memfd:foo (deleted)", 33, 6000)
	if got := (realProcResolver{}).resolve(1002); !got.Live || got.Exe != "memfd:foo" || got.StartTime != 6000 {
		t.Errorf("memfd exe: got %+v; want Live, Exe=memfd:foo, StartTime=6000", got)
	}

	// (c) a NON-fileless exe whose target exists on disk: EvalSymlinks
	// canonicalizes it; still Live.
	realTarget := filepath.Join(root, "realbin")
	if err := os.WriteFile(realTarget, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeProc(t, root, 1003, realTarget, 0, 7000)
	got := (realProcResolver{}).resolve(1003)
	if !got.Live || got.StartTime != 7000 {
		t.Errorf("live exe: got %+v; want Live, StartTime=7000", got)
	}
	if canon, _ := filepath.EvalSymlinks(realTarget); got.Exe != canon {
		t.Errorf("live exe Exe=%q want canonical %q", got.Exe, canon)
	}
}

// A gone/unreadable process (no /proc/<pid> entry → exe link unreadable) is NOT
// live: the resolver returns the fail-closed zero value.
func TestRealResolverGoneProcessNotLive(t *testing.T) {
	root := t.TempDir()
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()
	if got := (realProcResolver{}).resolve(4242); got.Live {
		t.Errorf("a nonexistent pid must not be Live: %+v", got)
	}
	if got := (realProcResolver{}).resolve(0); got.Live {
		t.Errorf("pid<=0 must not be Live: %+v", got)
	}
}

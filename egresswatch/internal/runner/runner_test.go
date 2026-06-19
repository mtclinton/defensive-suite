package runner

import (
	"context"
	"errors"
	"testing"
)

func TestExecExitCodes(t *testing.T) {
	ctx := context.Background()
	res, err := Exec{}.Run(ctx, "true")
	if err != nil {
		t.Fatalf("true: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("true exit=%d", res.ExitCode)
	}
	res, err = Exec{}.Run(ctx, "false")
	if err != nil {
		t.Fatalf("false: %v", err)
	}
	if res.ExitCode == 0 {
		t.Errorf("false exit=%d, want non-zero", res.ExitCode)
	}
}

func TestExecCapturesStdout(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "printf", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "hello" {
		t.Errorf("stdout=%q", res.Stdout)
	}
}

func TestExecNotFound(t *testing.T) {
	_, err := Exec{}.Run(context.Background(), "egresswatch-no-such-binary-xyz")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err=%v, want ErrNotFound", err)
	}
}

func TestFakeResponsesAndCalls(t *testing.T) {
	f := &Fake{Responses: map[string]Result{"ss -tunp": {Stdout: "out", ExitCode: 0}}}
	res, err := f.Run(context.Background(), "ss", "-tunp")
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "out" {
		t.Errorf("stdout=%q", res.Stdout)
	}
	if len(f.Calls) != 1 || f.Calls[0] != "ss -tunp" {
		t.Errorf("calls=%v", f.Calls)
	}
}

func TestFakeUnmappedIsNotFound(t *testing.T) {
	f := &Fake{}
	if _, err := f.Run(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err=%v, want ErrNotFound", err)
	}
}

func TestFakeInjectedError(t *testing.T) {
	sentinel := errors.New("boom")
	f := &Fake{Errs: map[string]error{"ss -tunp": sentinel}}
	if _, err := f.Run(context.Background(), "ss", "-tunp"); !errors.Is(err, sentinel) {
		t.Errorf("err=%v, want sentinel", err)
	}
}

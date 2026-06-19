// Package runner abstracts external command execution so checks can shell out to
// gitleaks/trufflehog in production and run against canned JSON output in tests.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Result is the captured outcome of a command. A non-zero ExitCode is returned
// without a Go error because tools like `gitleaks detect` exit non-zero to
// report that leaks were found.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner runs an external command and returns its captured output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

// ErrNotFound is returned (wrapped) when the executable is not on PATH, letting
// checks degrade to an informational "tool absent" finding instead of failing.
var ErrNotFound = errors.New("executable not found")

// Exec is the production Runner.
type Exec struct{}

// Run executes name with args, capturing stdout/stderr. A command that exits
// non-zero is reported via Result.ExitCode with a nil error.
func (Exec) Run(ctx context.Context, name string, args ...string) (Result, error) {
	if _, err := exec.LookPath(name); err != nil {
		return Result{}, fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	if err != nil {
		return res, err
	}
	return res, nil
}

// Fake is a Runner backed by canned responses, keyed by "name arg1 arg2 ...".
// It records every call in Calls for assertions.
type Fake struct {
	Responses map[string]Result
	Errs      map[string]error
	Calls     []string
}

func key(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}

// Run returns the canned Result/error for the call, or ErrNotFound if unmapped.
func (f *Fake) Run(_ context.Context, name string, args ...string) (Result, error) {
	k := key(name, args)
	f.Calls = append(f.Calls, k)
	if f.Errs != nil {
		if err, ok := f.Errs[k]; ok {
			return Result{}, err
		}
	}
	if f.Responses != nil {
		if r, ok := f.Responses[k]; ok {
			return r, nil
		}
	}
	return Result{}, fmt.Errorf("%s: %w", name, ErrNotFound)
}

//go:build !(linux && ebpf)

package main

import (
	"fmt"
	"os"
)

// runSensor is the default-build placeholder for the live eBPF magic-packet
// sensor. The real implementation lives in sensor_ebpf.go behind the
// `linux && ebpf` build tag and is excluded here so the default build stays
// stdlib-only with no cilium/ebpf dependency and no clang requirement. This stub
// explains how to build the sensor variant instead of silently failing.
func runSensor(args []string) int {
	_ = args
	fmt.Fprintln(os.Stderr, "egresswatch: the live eBPF magic-packet sensor is not in this build.")
	fmt.Fprintln(os.Stderr, "Build it on a Linux host with a BTF kernel and clang:")
	fmt.Fprintln(os.Stderr, "  go generate ./bpf/...            # bpf2go: compile magicpacket.bpf.c")
	fmt.Fprintln(os.Stderr, "  go build -tags ebpf -o egresswatch .")
	fmt.Fprintln(os.Stderr, "Then run as root:  sudo ./egresswatch sensor")
	fmt.Fprintln(os.Stderr, "Until then, the periodic `egresswatch triage` /proc scan covers the same signature.")
	return 1
}

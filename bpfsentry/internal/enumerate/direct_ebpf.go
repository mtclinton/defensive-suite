//go:build linux && ebpf

// Package enumerate's direct path uses cilium/ebpf to walk the kernel's program,
// map, and link tables via the BPF syscall (BPF_PROG_GET_NEXT_ID + GET_FD_BY_ID),
// without shelling out to bpftool. It is the deeper, Linux-only alternative to
// the portable JSON-parsing path.
//
// THIS FILE IS AN ARTIFACT, NOT PART OF THE DEFAULT BUILD. It is excluded unless
// you build with `-tags ebpf` on linux, which also pulls in the cilium/ebpf
// dependency. The default suite build is stdlib-only and offline-green, so this
// path is shipped as source for the Linux-only deployment that wants it, and is
// not compiled (and not depended on) by `go build ./...` / `go test ./...`.
//
// Like the bpftool path, this still reads the LIVE kernel and is therefore
// defeated by a sys_bpf-hooking rootkit — which is exactly why the out-of-band
// memory-forensics path (forensics/) exists. Use this for a richer live view
// (it can read used-helper bitmaps from prog_info), then diverge it against the
// offline prog_idr walk.
//
// To enable this path:
//
//	go get github.com/cilium/ebpf@latest      # adds the only external dependency
//	CGO_ENABLED=0 GOOS=linux go build -tags ebpf ./...
//
// The implementation below is intentionally a thin, dependency-isolated sketch:
// the production version calls ebpf.ProgramGetNextID / NewProgramFromID and reads
// ebpf.ProgramInfo. It is kept minimal so the tagged build stays small and the
// untagged default never references cilium/ebpf.
package enumerate

import (
	"context"
	"errors"
)

// ErrDirectStub is returned by the stubbed direct enumerator. The real
// implementation (behind this same build tag) replaces EnumerateDirect's body
// with cilium/ebpf calls once `go get github.com/cilium/ebpf` has been run in a
// Linux deployment that opts into the dependency.
var ErrDirectStub = errors.New("direct cilium/ebpf enumeration: build with -tags ebpf and wire cilium/ebpf (see direct_ebpf.go)")

// EnumerateDirect walks the kernel BPF tables via the BPF syscall (cilium/ebpf),
// returning the same normalized Inventory shape as the bpftool path so the two
// are interchangeable at the call site. Source is set to "ebpf".
//
// The signature matches the portable Enumerate by intent; the production body
// (cilium/ebpf) is added in the Linux-only deployment.
func EnumerateDirect(ctx context.Context) (Inventory, error) {
	// Real body, when cilium/ebpf is vendored:
	//
	//   var inv Inventory
	//   inv.Source = "ebpf"
	//   var id ebpf.ProgramID
	//   for {
	//       next, err := ebpf.ProgramGetNextID(id)
	//       if errors.Is(err, os.ErrNotExist) { break }
	//       if err != nil { return inv, err }
	//       p, err := ebpf.NewProgramFromID(next)
	//       ...
	//       info, _ := p.Info()
	//       inv.Programs = append(inv.Programs, Program{
	//           ID: int(next), Name: info.Name, Type: info.Type.String(), ...,
	//       })
	//       id = next
	//   }
	//   inv.sort()
	//   return inv, nil
	return Inventory{Source: "ebpf"}, ErrDirectStub
}

//go:build darwin || linux || windows

package oomprofile

import (
	"bytes"
	"runtime"
	"testing"
)

func TestOOMHeapRuntimeRecordLayout(t *testing.T) {
	// This package mirrors a private runtime ABI. Exercise the actual collector,
	// not a synthetic struct alone: an ABI drift otherwise dereferences counts as
	// stack addresses during the final-close power report.
	old := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	defer func() { runtime.MemProfileRate = old }()
	allocations := make([][]byte, 64)
	for i := range allocations {
		allocations[i] = make([]byte, 8192)
		allocations[i][0] = byte(i)
	}
	runtime.GC()
	runtime.GC()
	n, _ := runtimeMemProfileInternal(nil, true)
	records := make([]memProfileRecord, n+100)
	n, ok := runtimeMemProfileInternal(records, true)
	if !ok {
		t.Fatal("runtime heap profile outgrew bounded record margin")
	}
	sawFrame := false
	for _, record := range records[:n] {
		if record.ObjectSize <= 0 || record.AllocObjects < 0 || record.FreeObjects < 0 {
			t.Fatalf("invalid runtime record counters: size=%d alloc=%d free=%d", record.ObjectSize, record.AllocObjects, record.FreeObjects)
		}
		for _, pc := range record.Stack {
			if pc != 0 && runtime.FuncForPC(pc) != nil {
				sawFrame = true
				break
			}
		}
	}
	if !sawFrame {
		t.Fatal("runtime collector returned no resolvable stack")
	}
	for _, kind := range []string{"", "alloc_space"} {
		var output bytes.Buffer
		if err := writeHeapInternal(&output, kind); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(output.Bytes(), []byte("alloc_objects")) || !bytes.Contains(output.Bytes(), []byte("inuse_space")) {
			t.Fatal("heap profile omitted required sample kinds")
		}
		requireDecodedHeapProfile(t, output.Bytes())
	}
	runtime.KeepAlive(allocations)
	record := memProfileRecord{ObjectSize: 16, AllocObjects: 9, FreeObjects: 4}
	if record.InUseBytes() != 80 || record.InUseObjects() != 5 {
		t.Fatal("Go 1.27 object-size accounting differs from actual bytes")
	}
}

func TestOOMAdjacentRuntimeProfilesEncode(t *testing.T) {
	for _, kind := range []string{"goroutine", "threadcreate", "block", "mutex"} {
		t.Run(kind, func(t *testing.T) {
			var output bytes.Buffer
			if err := profileWriters[kind](&output); err != nil {
				t.Fatal(err)
			}
			fields, err := decodeProfileFields(output.Bytes())
			if err != nil || len(fields) == 0 {
				t.Fatalf("actual %s profile invalid: %v", kind, err)
			}
		})
	}
}

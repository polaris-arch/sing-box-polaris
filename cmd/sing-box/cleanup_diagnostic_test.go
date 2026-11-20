package main

import (
	"strings"
	"testing"
)

func TestCleanupDiagnosticPanicUsesFixedFallback(t *testing.T) {
	message := runtimeCleanupDiagnosticMessage(func() any { panic("private token and address") })
	if message != "runtime cleanup snapshot encoding unavailable" {
		t.Fatal("diagnostic did not use the fixed fallback")
	}
	if strings.Contains(message, "private") {
		t.Fatal("diagnostic disclosed panic")
	}
}

func TestCleanupDiagnosticEncodingFailureIsFixed(t *testing.T) {
	message := runtimeCleanupDiagnosticMessage(func() any { return make(chan string) })
	if message != "runtime cleanup snapshot encoding unavailable" {
		t.Fatal(message)
	}
}

func TestCleanupDiagnosticFiniteSnapshotIsEncoded(t *testing.T) {
	message := runtimeCleanupDiagnosticMessage(func() any {
		return struct {
			Phase uint32 `json:"phase"`
		}{7}
	})
	if message != `runtime cleanup snapshot: {"phase":7}` {
		t.Fatal(message)
	}
}

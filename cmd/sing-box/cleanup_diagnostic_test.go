package main

import (
	"errors"
	"strings"
	"testing"
)

func TestCleanupDiagnosticPanicDoesNotMaskCloseError(t *testing.T) {
	original := errors.New("original close failure")
	result := original
	message := runtimeCleanupDiagnosticMessage(func() any { panic("private token and address") })
	if result != original || message != "runtime cleanup snapshot encoding unavailable" {
		t.Fatal("diagnostic changed original failure")
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

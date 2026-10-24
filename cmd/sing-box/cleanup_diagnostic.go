package main

import "encoding/json"

// Observation failure must not panic over, replace, or suppress the original
// Close result. The callback is the fixed Box scalar snapshot, never config.
func runtimeCleanupDiagnosticMessage(snapshot func() any) (message string) {
	message = "runtime cleanup snapshot encoding unavailable"
	defer func() { _ = recover() }()
	encoded, err := json.Marshal(snapshot())
	if err == nil {
		message = "runtime cleanup snapshot: " + string(encoded)
	}
	return message
}

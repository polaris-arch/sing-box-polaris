package clashapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigReplacementReturnsUnsupportedWithoutFalseAcknowledgement(t *testing.T) {
	for _, body := range []string{"", `{}`, `{"path":"private-config.json","payload":"private-node-data"}`, `{invalid`} {
		t.Run(body, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/?force=true", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			// Nil collaborators prove this unsupported route neither accesses
			// an instance nor performs a mode change/reload before returning.
			configRouter(nil, nil).ServeHTTP(response, request)
			if response.Code != http.StatusNotImplemented {
				t.Fatalf("configuration replacement falsely acknowledged: %d", response.Code)
			}
			var result HTTPError
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil { t.Fatal(err) }
			if result.Message != "Configuration replacement is not implemented" { t.Fatal(result.Message) }
			if strings.Contains(response.Body.String(), "private-") { t.Fatal("request body leaked in response") }
			if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") { t.Fatal("error is not JSON") }
		})
	}
}

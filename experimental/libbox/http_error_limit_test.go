package libbox

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type countedErrorBody struct {
	read   int
	closed bool
}

func (b *countedErrorBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.read += len(p)
	return len(p), nil
}

func (b *countedErrorBody) Close() error {
	b.closed = true
	return nil
}

func TestHTTPErrorBodyBoundedAndClosed(t *testing.T) {
	body := &countedErrorBody{}
	response := &httpResponse{Response: &http.Response{Status: "500 Internal Server Error", Body: body}}
	message := response.errorString()
	if body.read != httpErrorBodyLimit+1 || !body.closed {
		t.Fatalf("read=%d closed=%v", body.read, body.closed)
	}
	if !strings.HasSuffix(message, " [truncated]") {
		t.Fatal("truncation not reported")
	}
}

func TestHTTPErrorSmallBodyPreserved(t *testing.T) {
	response := &httpResponse{Response: &http.Response{Status: "400 Bad Request", Body: io.NopCloser(strings.NewReader("details"))}}
	if got := response.errorString(); got != "HTTP 400 Bad Request: details" {
		t.Fatalf("unexpected error: %s", got)
	}
}

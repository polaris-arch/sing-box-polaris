package usagetrack

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type testBody struct { io.Reader; closed bool }
func (b *testBody) Close() error { b.closed = true; return nil }
type failedReader struct{}
func (failedReader) Read(p []byte) (int, error) { copy(p, "part"); return 4, errors.New("read failure") }

func TestPeekReplaysAllBytesAndClosesOriginal(t *testing.T) {
	for _, size := range []int{0, 8, 9, 100} {
		want := bytes.Repeat([]byte("x"), size)
		body := &testBody{Reader: bytes.NewReader(want)}
		captured, replay, complete, err := Peek(body, 8)
		if err != nil || complete != (size <= 8) { t.Fatal(size, complete, err) }
		got, err := io.ReadAll(replay)
		if err != nil || !bytes.Equal(got, want) { t.Fatal("business bytes changed") }
		if complete && !bytes.Equal(captured, want) { t.Fatal("capture differs") }
		if !complete && captured != nil { t.Fatal("overflow is not a valid body") }
		replay.Close()
		if !body.closed { t.Fatal("original body not closed") }
	}
}

func TestPeekReadErrorIsNotAReplayableTail(t *testing.T) {
	body := &testBody{Reader: failedReader{}}
	captured, _, complete, err := Peek(body, 8)
	if err == nil || complete || captured != nil { t.Fatal("read failure accepted") }
}

func TestCaptureOverflowDoesNotTruncateForwardedBytes(t *testing.T) {
	var business bytes.Buffer
	capture := &Capture{Limit: 8}
	want := bytes.Repeat([]byte("x"), 100)
	if _, err := io.Copy(io.MultiWriter(&business, capture), bytes.NewReader(want)); err != nil { t.Fatal(err) }
	if !bytes.Equal(want, business.Bytes()) || !capture.Incomplete || capture.Data != nil { t.Fatal("overflow contract broken") }
}

func TestLinesIncrementalBoundaryAndEOF(t *testing.T) {
	s := Lines{LineLimit: 8, TotalLimit: 32}
	var got [][]byte
	for _, chunk := range []string{"ab", "c\n", "de", "f"} { got = append(got, s.Feed([]byte(chunk), false)...)}
	got = append(got, s.Feed(nil, true)...)
	if s.Incomplete || len(got) != 2 || string(got[0]) != "abc" || string(got[1]) != "def" { t.Fatal(got) }
}

func TestLinesHugeUnterminatedAndTotalBudget(t *testing.T) {
	for _, limits := range [][2]int{{8, 100}, {100, 8}} {
		s := Lines{LineLimit: limits[0], TotalLimit: limits[1]}
		for i := 0; i < 10000; i++ { s.Feed([]byte("x"), false) }
		if !s.Incomplete || s.partial != nil || s.Feed([]byte("usage\n"), true) != nil { t.Fatal("unbounded or restarted accounting") }
	}
}

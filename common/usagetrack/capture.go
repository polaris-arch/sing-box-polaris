// Package usagetrack bounds optional accounting work without limiting proxy traffic.
package usagetrack

import (
	"bytes"
	"io"
)

// These are observation budgets, not request/response size limits. On overflow
// callers must report incomplete accounting and continue forwarding the stream.
const (
	BodyBudget   = 8 << 20
	LineBudget   = 1 << 20
	StreamBudget = 16 << 20
)

type replayBody struct {
	io.Reader
	io.Closer
}

// Peek restores all consumed bytes, including the overflow probe. A read error
// must abort the request: forwarding the remaining tail would corrupt it.
func Peek(body io.ReadCloser, limit int64) ([]byte, io.ReadCloser, bool, error) {
	prefix, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, body, false, err
	}
	replay := &replayBody{io.MultiReader(bytes.NewReader(prefix), body), body}
	if int64(len(prefix)) > limit {
		return nil, replay, false, nil
	}
	return prefix, replay, true, nil
}

type Capture struct {
	Data       []byte
	Limit      int
	Incomplete bool
}

func (c *Capture) Write(p []byte) (int, error) {
	if !c.Incomplete {
		if len(p) > c.Limit-len(c.Data) {
			c.Data = nil
			c.Incomplete = true
		} else {
			c.Data = append(c.Data, p...)
		}
	}
	return len(p), nil
}

// Lines scans only newly received bytes. It never repeatedly scans an unfinished
// line, and permanently disables accounting once either budget is exhausted.
type Lines struct {
	partial    []byte
	seen       int
	Incomplete bool
	LineLimit  int
	TotalLimit int
}

func (s *Lines) Feed(p []byte, eof bool) [][]byte {
	if s.Incomplete {
		return nil
	}
	if len(p) > s.TotalLimit-s.seen {
		s.partial = nil
		s.Incomplete = true
		return nil
	}
	s.seen += len(p)
	var lines [][]byte
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		end := i
		if end < 0 {
			end = len(p)
		}
		if end > s.LineLimit-len(s.partial) {
			s.partial = nil
			s.Incomplete = true
			return nil
		}
		s.partial = append(s.partial, p[:end]...)
		if i < 0 {
			break
		}
		lines = append(lines, s.partial)
		s.partial = nil
		p = p[i+1:]
	}
	if eof && len(s.partial) > 0 {
		lines = append(lines, s.partial)
		s.partial = nil
	}
	return lines
}

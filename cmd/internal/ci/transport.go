package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const responseHeaderLimit = 65536

type readLimits struct {
	Attempt, Total, RetryWait time.Duration
}

var (
	defaultReadLimits = readLimits{600 * time.Second, 1320 * time.Second, 120 * time.Second}
	githubGETPath     = regexp.MustCompile(`^repos/polaris-arch/sing-box-polaris/[A-Za-z0-9_./?=&%+\-]+$`)
	unknownMailZone   = regexp.MustCompile(`[ \t]-0000(?:[ \t]*\([^)]*\))?[ \t]*$`)
	responseStatus    = regexp.MustCompile(`^HTTP/\S+ ([0-9]{3})(?: .*)?$`)
)

type retryBudget struct {
	ExtraGETs int
	Wait      time.Duration
}

var processReadBudget retryBudget

type readFailure struct {
	Kind      string
	Status    int
	Headers   map[string]string
	Retryable bool
	Cleanup   bool
}

func (failure *readFailure) Error() string {
	message := "GitHub GET failed: " + failure.Kind
	if failure.Status != 0 {
		message += fmt.Sprintf(" HTTP %d", failure.Status)
	}
	if failure.Cleanup {
		message += "; child cleanup not confirmed"
	}
	return message
}

func retryStatus(status int) bool {
	return status == 500 || status == 502 || status == 503 || status == 504
}

func retryDelay(headers map[string]string, attempt int, now time.Time) (time.Duration, error) {
	value, present := headers["retry-after"]
	if !present {
		return time.Duration(min(1<<(attempt-1), 8)) * time.Second, nil
	}
	value = strings.TrimSpace(value)
	if value != "" && strings.IndexFunc(value, func(c rune) bool { return c < '0' || c > '9' }) == -1 {
		seconds, err := strconv.ParseUint(value, 10, 64)
		if err != nil || seconds > 120 {
			return 0, &readFailure{Kind: "retry budget exhausted"}
		}
		return time.Duration(seconds) * time.Second, nil
	}
	parsed, err := mail.ParseDate(value)
	if err != nil || unknownMailZone.MatchString(value) {
		return 0, &readFailure{Kind: "invalid Retry-After"}
	}
	return max(0, parsed.Sub(now)), nil
}

func readHeaders(raw []byte) (int, map[string]string, error) {
	lines := bytes.Split(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")), []byte{'\n'})
	match := responseStatus.FindSubmatch(lines[0])
	if match == nil {
		return 0, nil, &readFailure{Kind: "invalid response status"}
	}
	status, _ := strconv.Atoi(string(match[1]))
	headers := map[string]string{}
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		key, value, found := bytes.Cut(line, []byte{':'})
		if !found || bytes.IndexFunc(key, func(c rune) bool { return c > 127 }) >= 0 {
			return 0, nil, &readFailure{Kind: "invalid response header"}
		}
		name := strings.ToLower(string(key))
		switch name {
		case "date", "server", "content-type", "content-length", "retry-after", "x-github-request-id", "x-ms-request-id", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "x-ratelimit-resource":
			if _, duplicate := headers[name]; duplicate {
				return 0, nil, &readFailure{Kind: "duplicate diagnostic header"}
			}
			if bytes.IndexFunc(value, func(c rune) bool { return c > 127 }) >= 0 {
				return 0, nil, &readFailure{Kind: "invalid diagnostic header"}
			}
			text := strings.TrimSpace(string(value))
			if len(text) > 256 || strings.IndexFunc(text, func(c rune) bool { return c < 32 || c == 127 }) >= 0 {
				return 0, nil, &readFailure{Kind: "invalid diagnostic header"}
			}
			headers[name] = text
		}
	}
	return status, headers, nil
}

type pipeEvent struct {
	stream byte
	data   []byte
	err    error
}

func readPipe(pipe *os.File, stream byte, events chan<- pipeEvent, stop <-chan struct{}) {
	for {
		data := make([]byte, 65536)
		count, err := pipe.Read(data)
		select {
		case events <- pipeEvent{stream, data[:count], err}:
		case <-stop:
			return
		}
		if err != nil {
			return
		}
	}
}

type readResult struct {
	Bytes   int64             `json:"bytes"`
	SHA256  string            `json:"sha256"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
}

// Use owned pipes on both platforms. Waiting for gh and draining both streams
// are separate conditions, including EOF while the child is still alive.
func githubAttempt(ctx context.Context, path string, sink io.Writer, maximum int64, timeout time.Duration) (result readResult, err error) {
	if err := ctx.Err(); err != nil {
		return result, err
	}
	deadline := time.Now().Add(timeout)
	work := time.NewTimer(timeout - min(5*time.Second, timeout/2))
	defer work.Stop()
	out, outWriter, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer out.Close()
	defer outWriter.Close()
	stderr, errWriter, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer stderr.Close()
	defer errWriter.Close()
	child := exec.Command("gh", "api", "--include", "--method", "GET", path)
	child.Stdout, child.Stderr = outWriter, errWriter
	if err := child.Start(); err != nil {
		return result, &readFailure{Kind: "transport start"}
	}
	outWriter.Close()
	errWriter.Close()
	wait := make(chan error, 1)
	go func() { wait <- child.Wait() }()
	stop := make(chan struct{})
	events := make(chan pipeEvent, 2)
	go readPipe(out, 'o', events, stop)
	go readPipe(stderr, 'e', events, stop)
	waited := false
	defer func() {
		close(stop)
		out.Close()
		stderr.Close()
		if waited {
			return
		}
		child.Process.Kill()
		cleanup := time.NewTimer(min(5*time.Second, max(time.Millisecond, time.Until(deadline))))
		defer cleanup.Stop()
		select {
		case <-wait:
		case <-cleanup.C:
			var failure *readFailure
			if errors.As(err, &failure) {
				failure.Retryable, failure.Cleanup = false, true
			} else {
				err = errors.Join(err, fmt.Errorf("GitHub GET child cleanup not confirmed"))
			}
		}
	}()
	var prefix, errorsSeen []byte
	digest := sha256.New()
	var exit error
	streams := 2
	failure := func(kind string, retry bool) error {
		return &readFailure{Kind: kind, Status: result.Status, Headers: result.Headers, Retryable: retry}
	}
	for streams != 0 || !waited {
		select {
		case exit = <-wait:
			waited = true
			wait = nil
		case <-ctx.Done():
			return result, ctx.Err()
		case <-work.C:
			return result, failure("read deadline", result.Status == 0 || result.Status == 200 || retryStatus(result.Status))
		case event := <-events:
			if event.err != nil {
				if !errors.Is(event.err, io.EOF) {
					return result, failure("read stream", false)
				}
				streams--
			}
			data := event.data
			if event.stream == 'e' {
				errorsSeen = append(errorsSeen, data[:min(len(data), responseHeaderLimit-len(errorsSeen))]...)
				continue
			}
			if result.Status == 0 {
				prefix = append(prefix, data...)
				position, markerSize := bytes.Index(prefix, []byte("\r\n\r\n")), 4
				if alternative := bytes.Index(prefix, []byte("\n\n")); alternative >= 0 && (position < 0 || alternative < position) {
					position, markerSize = alternative, 2
				}
				if position < 0 {
					if len(prefix) > responseHeaderLimit {
						return result, failure("response header limit", false)
					}
					continue
				}
				if position > responseHeaderLimit {
					return result, failure("response header limit", false)
				}
				result.Status, result.Headers, err = readHeaders(prefix[:position])
				if err != nil {
					return result, err
				}
				data, prefix = prefix[position+markerSize:], nil
			}
			if result.Status == 200 || result.Status == 204 {
				if int64(len(data)) > maximum-result.Bytes {
					return result, failure("response size limit", false)
				}
				if _, err := sink.Write(data); err != nil {
					return result, err
				}
				digest.Write(data)
				result.Bytes += int64(len(data))
			}
		}
	}
	knownNetworkError := false
	lowerErrors := bytes.ToLower(errorsSeen)
	for _, text := range []string{"connection reset by peer", "connection timed out", "i/o timeout", "tls handshake timeout", "client.timeout exceeded", "unexpected eof"} {
		knownNetworkError = knownNetworkError || bytes.Contains(lowerErrors, []byte(text))
	}
	if result.Status != 200 && result.Status != 204 {
		kind := "HTTP response"
		if result.Status == 0 {
			kind = "missing response"
		}
		return result, failure(kind, retryStatus(result.Status) || result.Status == 0 && knownNetworkError)
	}
	if exit != nil {
		return result, failure("transport exit", knownNetworkError)
	}
	result.SHA256 = fmt.Sprintf("%x", digest.Sum(nil))
	return result, nil
}

func readGitHub(path string, sink *os.File, maximum int64, budget *retryBudget, limits readLimits, record func(map[string]any)) (readResult, error) {
	return readGitHubFile(context.Background(), path, sink, maximum, budget, limits, record)
}

func readGitHubFile(ctx context.Context, path string, sink *os.File, maximum int64, budget *retryBudget, limits readLimits, record func(map[string]any)) (readResult, error) {
	return readGitHubSink(ctx, path, sink, func() error {
		if _, err := sink.Seek(0, io.SeekStart); err != nil {
			return err
		}
		return sink.Truncate(0)
	}, maximum, budget, limits, record)
}

func readGitHubSink(ctx context.Context, path string, sink io.Writer, reset func() error, maximum int64, budget *retryBudget, limits readLimits, record func(map[string]any)) (readResult, error) {
	if path != "rate_limit" && path != "repos/"+repository && !githubGETPath.MatchString(path) || slices.Contains(strings.Split(strings.SplitN(path, "?", 2)[0], "/"), "..") {
		return readResult{}, &readFailure{Kind: "unapproved GET path"}
	}
	if maximum <= 0 || limits.Attempt <= 0 || limits.Attempt > defaultReadLimits.Attempt || limits.Total <= 0 || limits.Total > defaultReadLimits.Total || limits.RetryWait <= 0 || limits.RetryWait > defaultReadLimits.RetryWait {
		return readResult{}, &readFailure{Kind: "invalid read limit"}
	}
	if budget == nil {
		budget = &processReadBudget
	}
	deadline := time.Now().Add(limits.Total)
	for attempt := 1; attempt <= 3; attempt++ {
		if err := reset(); err != nil {
			return readResult{}, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return readResult{}, &readFailure{Kind: "total read deadline"}
		}
		result, err := githubAttempt(ctx, path, sink, maximum, min(limits.Attempt, remaining))
		if record != nil {
			headers := result.Headers
			if headers == nil {
				headers = map[string]string{}
			}
			var status any
			if result.Status != 0 {
				status = result.Status
			}
			var kind any
			if err != nil {
				var failure *readFailure
				if errors.As(err, &failure) {
					kind = failure.Kind
				} else {
					kind = "transport error"
				}
			}
			fields := map[string]any{"readAttempt": attempt, "readStatus": status, "readHeaders": headers, "readError": kind, "extraGETs": budget.ExtraGETs}
			if err == nil {
				fields["readBytes"] = result.Bytes
			}
			record(fields)
		}
		if err == nil {
			return result, nil
		}
		if resetErr := reset(); resetErr != nil {
			return readResult{}, errors.Join(err, resetErr)
		}
		var failure *readFailure
		if !errors.As(err, &failure) || !failure.Retryable || attempt == 3 || budget.ExtraGETs >= 8 {
			return readResult{}, err
		}
		delay, err := retryDelay(failure.Headers, attempt, time.Now())
		if err != nil {
			return readResult{}, err
		}
		if delay >= time.Until(deadline) || delay > limits.RetryWait-budget.Wait {
			return readResult{}, &readFailure{Kind: "retry budget exhausted", Status: failure.Status}
		}
		budget.ExtraGETs++
		budget.Wait += delay
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return readResult{}, ctx.Err()
		case <-timer.C:
		}
	}
	panic("unreachable GitHub read attempt")
}

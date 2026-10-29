//go:build !windows && with_clash_api

package box_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

// This subprocess is an actual owned executable, not an alternative Start path.
// It speaks Tor's controller and SOCKS protocols on real local listeners. The
// production process creator, authentication, proxy bridge, readiness, unique
// Wait, graph publication and tempdir cleanup all remain connected.
func TestRuntimeTorNativeHelper(t *testing.T) {
	if os.Getenv("POLARIS_TOR_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	value := func(key string) string {
		for i, arg := range args {
			if arg == key && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(21)
	}
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(22)
	}
	if err = os.WriteFile(value("--ControlPortWriteToFile"), []byte("PORT="+controlListener.Addr().String()+"\n"), 0o600); err != nil {
		os.Exit(23)
	}
	metadata := map[string]any{"pid": os.Getpid(), "dataDir": value("--DataDirectory"), "control": controlListener.Addr().String(), "socks": socksListener.Addr().String()}
	encoded, _ := json.Marshal(metadata)
	_ = os.WriteFile(value("--TestMetadata"), encoded, 0o600)
	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}
			go torHelperSOCKS(conn)
		}
	}()
	conn, err := controlListener.Accept()
	if err != nil {
		os.Exit(24)
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			os.Exit(0)
		}
		line = strings.TrimSpace(line)
		response := "250 OK\r\n"
		switch line {
		case "PROTOCOLINFO":
			state, _ := os.ReadFile(value("--TestReadiness"))
			if string(state) == "auth-block" {
				select {}
			}
			response = "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250-VERSION Tor=\"0.4.8.1\"\r\n250 OK\r\n"
		case "GETCONF DisableNetwork":
			response = "250 DisableNetwork=1\r\n"
		case "GETINFO status/bootstrap-phase":
			state, _ := os.ReadFile(value("--TestReadiness"))
			switch string(state) {
			case "block":
				select {}
			case "error":
				response = "250-status/bootstrap-phase=ERR BOOTSTRAP PROGRESS=50 WARNING=fixture\r\n250 OK\r\n"
			default:
				progress := "50"
				if string(state) == "100" {
					progress = "100"
				}
				response = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=" + progress + "\r\n250 OK\r\n"
			}
		case "GETINFO net/listeners/socks":
			response = "250-net/listeners/socks=\"" + socksListener.Addr().String() + "\"\r\n250 OK\r\n"
		case "QUIT", "SIGNAL HALT":
			_, _ = io.WriteString(conn, response)
			os.Exit(0)
		}
		if _, err = io.WriteString(conn, response); err != nil {
			os.Exit(0)
		}
	}
}

func torHelperSOCKS(conn net.Conn) {
	defer conn.Close()
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return
	}
	var host string
	switch request[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		b := make([]byte, 1)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		b = make([]byte, int(b[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return
	}
	upstream, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))))
	if err != nil {
		return
	}
	defer upstream.Close()
	if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	var copy sync.WaitGroup
	copy.Go(func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close() })
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	copy.Wait()
}

func torGraphPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func TestRuntimeTorGraphManagedStartAndReadiness(t *testing.T) {
	for _, scenario := range []string{"direct-baseline", "unselected", "selected", "bootstrap-error", "blocked-control", "start-close-race"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			stateFile := filepath.Join(directory, "readiness")
			metadataFile := filepath.Join(directory, "process.json")
			state := "50"
			if scenario == "bootstrap-error" {
				state = "error"
			}
			if scenario == "blocked-control" {
				state = "block"
			}
			if scenario == "start-close-race" {
				state = "auth-block"
			}
			if err := os.WriteFile(stateFile, []byte(state), 0o600); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			launcher := filepath.Join(directory, "tor-helper")
			script := "#!/bin/sh\nPOLARIS_TOR_TEST_HELPER=1 exec '" + strings.ReplaceAll(executable, "'", "'\\''") + "' -test.run '^TestRuntimeTorNativeHelper$' -- \"$@\"\n"
			if err = os.WriteFile(launcher, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			mixedPort, apiPort := torGraphPort(t), torGraphPort(t)
			outbounds := []map[string]any{{"type": "direct", "tag": "direct"}}
			if scenario != "direct-baseline" {
				outbounds = append(outbounds, map[string]any{"type": "tor", "tag": "tor", "executable_path": launcher, "extra_args": []string{"--TestReadiness", stateFile, "--TestMetadata", metadataFile}})
			}
			chosen := "direct"
			if scenario == "selected" || scenario == "bootstrap-error" {
				chosen = "tor"
			}
			selector := map[string]any{"type": "selector", "tag": "proxy", "outbounds": []string{"direct"}, "default": chosen}
			if scenario != "direct-baseline" {
				selector["outbounds"] = []string{"direct", "tor"}
			}
			outbounds = append(outbounds, selector)
			content, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []map[string]any{{"type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": mixedPort}}, "outbounds": outbounds, "route": map[string]any{"final": "proxy"}, "experimental": map[string]any{"clash_api": map[string]any{"external_controller": fmt.Sprintf("127.0.0.1:%d", apiPort)}}})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			registry := include.Context(ctx)
			var options option.Options
			if err = singJSON.UnmarshalContext(registry, content, &options); err != nil {
				t.Fatal(err)
			}
			instance, err := box.New(box.Options{Context: registry, Options: options})
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			defer func() {
				if !closed {
					if err := instance.Close(); err != nil {
						t.Error(err)
					}
				}
			}()
			started := make(chan error, 1)
			go func() { started <- instance.Start() }()
			if scenario == "start-close-race" {
				for {
					if _, err = os.Stat(metadataFile); err == nil {
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("owned process was not created")
					case <-time.After(10 * time.Millisecond):
					}
				}
				closeDone := make(chan error, 1)
				go func() { closeDone <- instance.CloseWithResult() }()
				select {
				case err = <-started:
					if err == nil {
						t.Fatal("canceled Start succeeded")
					}
				case <-ctx.Done():
					t.Fatal("Start did not join canceled authentication")
				}
				select {
				case err = <-closeDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("Start/Close race did not join actual process")
				}
				closed = true
				encoded, err := os.ReadFile(metadataFile)
				if err != nil {
					t.Fatal(err)
				}
				var metadata struct{ DataDir, Control, Socks string }
				if err = json.Unmarshal(encoded, &metadata); err != nil {
					t.Fatal(err)
				}
				if _, err = os.Stat(metadata.DataDir); !os.IsNotExist(err) {
					t.Fatalf("racing process tempdir not retired: %v", err)
				}
				for _, address := range []string{metadata.Control, metadata.Socks} {
					conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
					if err == nil {
						_ = conn.Close()
						t.Fatal("racing process listener survived actual Wait")
					}
				}
				return
			}
			select {
			case err = <-started:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("Tor network bootstrap blocked entire graph")
			}
			if scenario == "selected" || scenario == "bootstrap-error" {
				selected, ok := instance.Outbound().Outbound("tor")
				if !ok {
					t.Fatal("actual Tor outbound unavailable")
				}
				if scenario == "selected" {
					canceled, stop := context.WithCancel(ctx)
					stop()
					if conn, dialErr := selected.DialContext(canceled, "tcp", M.ParseSocksaddr("127.0.0.1:1")); dialErr == nil || !errors.Is(dialErr, context.Canceled) {
						if conn != nil {
							_ = conn.Close()
						}
						t.Fatalf("selected readiness ignored cancellation: %v", dialErr)
					}
				} else {
					failed, stop := context.WithTimeout(ctx, time.Second)
					conn, dialErr := selected.DialContext(failed, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
					stop()
					if conn != nil {
						_ = conn.Close()
					}
					if dialErr == nil || !strings.Contains(dialErr.Error(), "bootstrap") || !strings.Contains(dialErr.Error(), "fixture") {
						t.Fatalf("bootstrap failure was lost: %v", dialErr)
					}
				}
			}
			apiClient := &http.Client{Timeout: time.Second}
			apiResponse, err := apiClient.Get(fmt.Sprintf("http://127.0.0.1:%d/version", apiPort))
			if err != nil {
				t.Fatal("API was not published", err)
			}
			_ = apiResponse.Body.Close()
			if apiResponse.StatusCode != http.StatusOK {
				t.Fatal("API did not serve request", apiResponse.StatusCode)
			}
			apiClient.CloseIdleConnections()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "local-data-plane") }))
			defer target.Close()
			proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 200 * time.Millisecond}
			response, requestErr := client.Get(target.URL)
			if scenario == "selected" || scenario == "bootstrap-error" {
				if requestErr == nil {
					_ = response.Body.Close()
					if response.StatusCode == http.StatusOK {
						t.Fatal("unready Tor was reported as ready")
					}
				}
				if scenario == "selected" {
					if err = os.WriteFile(stateFile, []byte("100"), 0o600); err != nil {
						t.Fatal(err)
					}
					client.Timeout = 3 * time.Second
					response, requestErr = client.Get(target.URL)
				}
			}
			if scenario != "bootstrap-error" {
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				body, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if string(body) != "local-data-plane" {
					t.Fatal("wrong data-plane response")
				}
			}
			if err = instance.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
			for _, address := range []string{fmt.Sprintf("127.0.0.1:%d", mixedPort), fmt.Sprintf("127.0.0.1:%d", apiPort)} {
				conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
				if err == nil {
					_ = conn.Close()
					t.Fatal("graph listener survived close")
				}
			}
			if scenario != "direct-baseline" {
				encoded, err := os.ReadFile(metadataFile)
				if err != nil {
					t.Fatal(err)
				}
				var metadata struct{ DataDir, Control, Socks string }
				if err = json.Unmarshal(encoded, &metadata); err != nil {
					t.Fatal(err)
				}
				if _, err = os.Stat(metadata.DataDir); !os.IsNotExist(err) {
					t.Fatalf("process tempdir not retired: %v", err)
				}
				for _, address := range []string{metadata.Control, metadata.Socks} {
					conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
					if err == nil {
						_ = conn.Close()
						t.Fatal("process listener survived actual Wait")
					}
				}
			}
		})
	}
}

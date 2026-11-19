package clashapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid/v5"
)

func connectionRouter(ctx context.Context, network adapter.NetworkManager, trafficManager *trafficcontrol.Manager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConnections(trafficManager))
	r.Delete("/", closeAllConnections(ctx, network, trafficManager))
	r.Delete("/{id}", closeConnection(trafficManager))
	return r
}

func connectionsSnapshot(trafficManager *trafficcontrol.Manager) render.M {
	uplinkTotal, downlinkTotal := trafficManager.Total()
	connections := common.Filter(trafficManager.Connections(), func(metadata *trafficcontrol.TrackerMetadata) bool {
		return metadata.OutboundType != C.TypeDNS
	})
	return render.M{
		"downloadTotal": downlinkTotal,
		"uploadTotal":   uplinkTotal,
		"connections": common.Map(connections, func(metadata *trafficcontrol.TrackerMetadata) *connectionObject {
			return (*connectionObject)(metadata)
		}),
		"memory": inuseMemory(),
	}
}

type connectionObject trafficcontrol.TrackerMetadata

func (c *connectionObject) MarshalJSON() ([]byte, error) {
	var inbound string
	if c.Metadata.Inbound != "" {
		inbound = c.Metadata.InboundType + "/" + c.Metadata.Inbound
	} else {
		inbound = c.Metadata.InboundType
	}
	var domain string
	if c.Metadata.Domain != "" {
		domain = c.Metadata.Domain
	} else {
		domain = c.Metadata.Destination.Fqdn
	}
	var processPath string
	if c.Metadata.ProcessInfo != nil {
		if len(c.Metadata.ProcessInfo.ProcessPaths) > 0 {
			processPath = c.Metadata.ProcessInfo.ProcessPaths[0]
		} else if len(c.Metadata.ProcessInfo.PackageNames) > 0 {
			processPath = c.Metadata.ProcessInfo.PackageNames[0]
		}
		if processPath == "" {
			if c.Metadata.ProcessInfo.UserId != -1 {
				processPath = F.ToString(c.Metadata.ProcessInfo.UserId)
			}
		} else if c.Metadata.ProcessInfo.UserName != "" {
			processPath = F.ToString(processPath, " (", c.Metadata.ProcessInfo.UserName, ")")
		} else if c.Metadata.ProcessInfo.UserId != -1 {
			processPath = F.ToString(processPath, " (", c.Metadata.ProcessInfo.UserId, ")")
		}
	}
	var rule string
	if c.Rule != nil {
		rule = F.ToString(c.Rule, " => ", c.Rule.Action())
	} else {
		rule = "final"
	}
	return json.Marshal(map[string]any{
		"id": c.ID,
		"metadata": map[string]any{
			"network":         c.Metadata.Network,
			"type":            inbound,
			"sourceIP":        c.Metadata.Source.Addr,
			"destinationIP":   c.Metadata.Destination.Addr,
			"sourcePort":      F.ToString(c.Metadata.Source.Port),
			"destinationPort": F.ToString(c.Metadata.Destination.Port),
			"host":            domain,
			"dnsMode":         "normal",
			"processPath":     processPath,
		},
		"upload":      c.Upload.Load(),
		"download":    c.Download.Load(),
		"start":       c.CreatedAt,
		"chains":      c.Chain,
		"rule":        rule,
		"rulePayload": "",
	})
}

// Bound full-table snapshots to at most 10 Hz per subscription. Keep accepting
// positive sub-100ms requests, but clamp their effective cadence instead of
// breaking clients that use them. The default remains one second.
const minimumConnectionSnapshotInterval = 100 * time.Millisecond

// Bound the entire snapshot write, including all continuation frames.
const connectionSnapshotWriteTimeout = 5 * time.Second

func connectionSnapshotInterval(raw string) (time.Duration, bool) {
	if raw == "" {
		return time.Second, true
	}
	milliseconds, err := strconv.ParseInt(raw, 10, 64)
	// Check before multiplication: positive int64 milliseconds can overflow a
	// Duration into zero, negative, or a tiny positive busy-loop interval.
	const maximumMilliseconds = int64((1<<63 - 1) / time.Millisecond)
	if err != nil || milliseconds <= 0 || milliseconds > maximumMilliseconds {
		return 0, false
	}
	interval := time.Duration(milliseconds) * time.Millisecond
	if interval < minimumConnectionSnapshotInterval {
		interval = minimumConnectionSnapshotInterval
	}
	return interval, true
}

func writeConnectionSnapshot(writer *wsutil.Writer, trafficManager *trafficcontrol.Manager) error {
	uplinkTotal, downlinkTotal := trafficManager.Total()
	connections := trafficManager.Connections()
	memory := inuseMemory()

	// Encode one row at a time. Encoding the entire object would accumulate all
	// its JSON before the WebSocket writer could send the first fragment.
	if _, err := io.WriteString(writer, `{"connections":[`); err != nil {
		return err
	}
	first := true
	for _, metadata := range connections {
		if metadata.OutboundType == C.TypeDNS {
			continue
		}
		if !first {
			if _, err := io.WriteString(writer, ","); err != nil {
				return err
			}
		}
		first = false
		row, err := (*connectionObject)(metadata).MarshalJSON()
		if err != nil {
			return err
		}
		if _, err = writer.Write(row); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, `],"downloadTotal":%d,"memory":%d,"uploadTotal":%d}`+"\n", downlinkTotal, memory, uplinkTotal); err != nil {
		return err
	}
	return writer.Flush()
}

func getConnections(trafficManager *trafficcontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	upgrader := ws.HTTPUpgrader{Timeout: connectionSnapshotWriteTimeout}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			render.JSON(w, r, connectionsSnapshot(trafficManager))
			return
		}

		interval, valid := connectionSnapshotInterval(r.URL.Query().Get("interval"))
		if !valid {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		conn, _, _, err := upgrader.Upgrade(r, w)
		if conn != nil {
			defer conn.Close()
		}
		if err != nil {
			return
		}
		ctx := r.Context()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()

		writer := wsutil.NewWriter(conn, ws.StateServerSide, ws.OpText)
		sendSnapshot := func() error {
			if err := conn.SetWriteDeadline(time.Now().Add(connectionSnapshotWriteTimeout)); err != nil {
				return err
			}
			return writeConnectionSnapshot(writer, trafficManager)
		}

		if err = sendSnapshot(); err != nil {
			return
		}

		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			if err = sendSnapshot(); err != nil {
				break
			}
		}
	}
}

func closeConnection(trafficManager *trafficcontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := uuid.FromStringOrNil(chi.URLParam(r, "id"))
		targetConnection := trafficManager.Connection(id)
		if targetConnection != nil {
			targetConnection.Close()
		}
		render.NoContent(w, r)
	}
}

func closeAllConnections(ctx context.Context, network adapter.NetworkManager, trafficManager *trafficcontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		trafficManager.CloseAllConnections()
		network.ResetNetwork(ctx)
		render.NoContent(w, r)
	}
}

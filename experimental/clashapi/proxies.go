package clashapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badjson"
	N "github.com/sagernet/sing/common/network"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyRouter(server *Server, router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName(server))
		r.Get("/", getProxy(server))
		r.Get("/delay", getProxyDelay(server))
		r.Put("/", updateProxy)
	})
	return r
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProxyName).(string)
			proxy, exist := server.outbound.Outbound(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func proxyInfo(server *Server, detour adapter.Outbound) *badjson.JSONObject {
	var info badjson.JSONObject
	var clashType string
	switch detour.Type() {
	case C.TypeBlock:
		clashType = "Reject"
	default:
		clashType = C.ProxyDisplayName(detour.Type())
	}
	info.Put("type", clashType)
	info.Put("name", detour.Tag())
	info.Put("udp", common.Contains(detour.Network(), N.NetworkUDP))
	delayHistory := server.urlTestHistory.LoadURLTestHistory(group.RealTag(detour, N.NetworkTCP))
	if delayHistory != nil {
		info.Put("history", []*adapter.URLTestHistory{delayHistory})
	} else {
		info.Put("history", []*adapter.URLTestHistory{})
	}
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		var now string
		if selected := group.Selected(N.NetworkTCP); selected != nil {
			now = selected.Tag()
		}
		info.Put("now", now)
		info.Put("all", group.All())
	}
	return &info
}

func getProxies(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var proxyMap badjson.JSONObject
		outbounds := common.Filter(server.outbound.Outbounds(), func(detour adapter.Outbound) bool {
			return detour.Tag() != ""
		})
		outbounds = append(outbounds, common.Map(common.Filter(server.endpoint.Endpoints(), func(detour adapter.Endpoint) bool {
			return detour.Tag() != ""
		}), func(it adapter.Endpoint) adapter.Outbound {
			return it
		})...)

		allProxies := make([]string, 0, len(outbounds))

		for _, detour := range outbounds {
			switch detour.Type() {
			case C.TypeDirect, C.TypeBlock, C.TypeDNS:
				continue
			}
			allProxies = append(allProxies, detour.Tag())
		}

		defaultTag := server.outbound.Default().Tag()

		sort.SliceStable(allProxies, func(i, j int) bool {
			return allProxies[i] == defaultTag
		})

		// fix clash dashboard
		proxyMap.Put("GLOBAL", map[string]any{
			"type":    "Fallback",
			"name":    "GLOBAL",
			"udp":     true,
			"history": []*adapter.URLTestHistory{},
			"all":     allProxies,
			"now":     defaultTag,
		})

		for i, detour := range outbounds {
			var tag string
			if detour.Tag() == "" {
				tag = F.ToString(i)
			} else {
				tag = detour.Tag()
			}
			proxyMap.Put(tag, proxyInfo(server, detour))
		}
		var responseMap badjson.JSONObject
		responseMap.Put("proxies", &proxyMap)
		response, err := responseMap.MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

func getProxy(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		response, err := proxyInfo(server, proxy).MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

type UpdateProxyRequest struct {
	Name string `json:"name"`
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := UpdateProxyRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
	selector, ok := proxy.(interface{ SelectOutbound(string) bool })
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector"))
		return
	}

	if !selector.SelectOutbound(req.Name) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Selector update error: not found"))
		return
	}

	render.NoContent(w, r)
}

func groupContains(outboundManager adapter.OutboundManager, outboundGroup adapter.OutboundGroup, tag string, visited map[string]bool) bool {
	for _, memberTag := range outboundGroup.All() {
		if memberTag == tag {
			return true
		}
		member, loaded := outboundManager.Outbound(memberTag)
		if !loaded {
			continue
		}
		if group.RealTag(member, N.NetworkTCP) == tag {
			return true
		}
		memberGroup, isGroup := member.(adapter.OutboundGroup)
		if !isGroup || visited[memberTag] {
			continue
		}
		visited[memberTag] = true
		if groupContains(outboundManager, memberGroup, tag, visited) {
			return true
		}
	}
	return false
}

func getProxyDelay(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		url := query.Get("url")
		if strings.HasPrefix(url, "http://") {
			url = ""
		}
		timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		ctx, cancel := context.WithTimeout(server.ctx, time.Millisecond*time.Duration(timeout))
		stopRequest := context.AfterFunc(r.Context(), cancel)
		defer func() { stopRequest(); cancel() }()
		if r.Context().Err() != nil {
			cancel()
		}
		history := server.urlTestHistory
		manager := server.outbound
		probe, connected, admissionErr := urltest.AcquireRuntimeProbeFromContext(server.ctx, ctx, proxy.Tag())
		if connected {
			if admissionErr != nil {
				render.Status(r, http.StatusServiceUnavailable)
				render.JSON(w, r, newError("Probe target or network is not ready"))
				return
			}
			defer probe.Release()
			proxy, manager, history, ctx = probe.Outbound(), probe.OutboundManager(), probe.History(), probe.Context()
		}
		target, realTag := group.URLTestTarget(proxy, N.NetworkTCP)
		epoch := history.Epoch()
		probeCtx, stopProbe, admissionErr := history.ProbeContext(ctx, epoch)
		if target == nil || admissionErr != nil {
			if stopProbe != nil {
				stopProbe()
			}
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("Probe target or network is not ready"))
			return
		}
		defer stopProbe()
		delay, err := urltest.URLTest(probeCtx, url, target)
		committed := false
		// The request cancellation callback may still be waiting to run.
		if r.Context().Err() == nil && probeCtx.Err() == nil {
			if connected {
				var value *adapter.URLTestHistory
				if err == nil {
					value = &adapter.URLTestHistory{Time: time.Now(), Delay: delay}
				}
				committed = urltest.PublishRuntimeResult(probeCtx, epoch, realTag, value)
				if committed {
					group.PerformRuntimeUpdateChecks(probeCtx, epoch, realTag)
				}
			} else if err != nil {
				committed = history.DeleteIfCurrent(epoch, realTag)
			} else {
				committed = history.StoreIfCurrent(epoch, realTag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
			}
		}
		if committed && !connected {
			for _, detour := range manager.Outbounds() {
				urlTestGroup, ok := detour.(adapter.URLTestGroup)
				if ok && groupContains(manager, urlTestGroup, realTag, map[string]bool{detour.Tag(): true}) {
					urlTestGroup.PerformUpdateCheck()
				}
			}
		}
		if r.Context().Err() != nil || ctx.Err() != nil {
			render.Status(r, http.StatusGatewayTimeout)
			render.JSON(w, r, ErrRequestTimeout)
			return
		}
		if !committed || !history.IsCurrent(epoch) || (connected && !probe.IsCurrent()) {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("Probe result is no longer current"))
			return
		}

		if err != nil || delay == 0 {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("An error occurred in the delay test"))
			return
		}

		render.JSON(w, r, render.M{
			"delay": delay,
		})
	}
}

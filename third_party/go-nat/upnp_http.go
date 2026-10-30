// Polaris changes: caller-captured XML/SOAP HTTP and joined SSDP requests.
// Original module identity and complete license: UPSTREAM.json and LICENSE.

package nat

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/soap"
	"github.com/koron/go-ssdp"
)

func newUPNPNAT(ctx context.Context, client upnp_NAT_Client, typ string, root *goupnp.RootDevice) (*upnp_NAT, error) {
	if root == nil {
		return nil, errors.New("UPnP gateway has no device description")
	}
	gateway := &upnp_NAT{c: client, typ: typ, rootDevice: root, ports: make(map[int]int)}
	if discoveryHTTPClient(ctx) == nil {
		return gateway, nil
	}
	// Resolve while this discovery worker and its captured generation are live.
	// Later metadata/selection/Add calls only read this immutable numeric value.
	host := root.URLBase.Hostname()
	if host == "" {
		return nil, errors.New("UPnP device URL has no host")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		resolve, _ := ctx.Value(discoveryResolverKey{}).(func(context.Context, string) ([]net.IP, error))
		if resolve == nil {
			return nil, errors.New("UPnP hostname requires the captured device resolver")
		}
		addresses, err := resolve(ctx, host)
		if err != nil {
			return nil, errors.Join(err, ctx.Err())
		}
		for _, address := range addresses {
			if address.To4() != nil {
				ip = address
				break
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, errors.New("UPnP gateway has no captured IPv4 device address")
	}
	gateway.capturedDevice = true
	gateway.deviceAddress = append(net.IP(nil), ip.To4()...)
	return gateway, nil
}

func discoveryHTTPClient(ctx context.Context) *http.Client {
	client, _ := ctx.Value(discoveryHTTPClientKey{}).(*http.Client)
	return client
}

func upnpSOAPClient(ctx context.Context, service *goupnp.Service) *soap.SOAPClient {
	client := service.NewSOAPClient()
	if captured := discoveryHTTPClient(ctx); captured != nil {
		client.HTTPClient = *captured
	}
	return client
}

func discoverUPNPDevices(ctx context.Context, target string) ([]goupnp.MaybeRootDevice, error) {
	if discoveryHTTPClient(ctx) == nil {
		// Preserve the upstream non-injected entry for existing library callers.
		return goupnp.DiscoverDevicesCtx(ctx, target)
	}
	return discoverUPNPDevicesWithSearch(ctx, target, ssdp.Search)
}

func discoverUPNPDevicesWithSearch(ctx context.Context, target string, search func(string, int, string) ([]ssdp.Service, error)) ([]goupnp.MaybeRootDevice, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Use the library's existing synchronous multi-interface SSDP provider for
	// the same target and three discovery requests. Unlike goupnp's private
	// HTTPU cancellation helper, it leaves no detached callback behind. All
	// three requests remain owned until return even if ctx has been canceled.
	var workers sync.WaitGroup
	var services [3][]ssdp.Service
	var searchErrors [3]error
	for i := range services {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			services[index], searchErrors[index] = search(target, 2, "")
		}(i)
	}
	workers.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var results []goupnp.MaybeRootDevice
	seen := make(map[string]bool)
	for _, batch := range services {
		for _, device := range batch {
			key := device.USN + "\x00" + device.Location
			if seen[key] {
				continue
			}
			seen[key] = true
			location, err := url.Parse(device.Location)
			result := goupnp.MaybeRootDevice{USN: device.USN, Location: location, Err: err}
			if err == nil {
				result.Root, result.Err = upnpDeviceByURL(ctx, location)
			}
			results = append(results, result)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
	}
	if len(results) == 0 {
		return nil, errors.Join(searchErrors[:]...)
	}
	return results, nil
}

func upnpDeviceByURL(ctx context.Context, location *url.URL) (*goupnp.RootDevice, error) {
	client := discoveryHTTPClient(ctx)
	if client == nil {
		return goupnp.DeviceByURLCtx(ctx, location)
	}
	if location == nil || location.Hostname() == "" || (location.Scheme != "http" && location.Scheme != "https") {
		return nil, errors.New("invalid UPnP device HTTP URL")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	var root goupnp.RootDevice
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("UPnP device HTTP status %d", response.StatusCode)
	} else {
		decoder := xml.NewDecoder(response.Body)
		decoder.DefaultSpace = goupnp.DeviceXMLNamespace
		decoder.CharsetReader = goupnp.CharsetReaderDefault
		err = decoder.Decode(&root)
	}
	// A caller-owned body may join reads, callbacks and a late close. Returning
	// from discovery never precedes that actual completion, even on XML error.
	err = errors.Join(err, response.Body.Close(), ctx.Err())
	if err != nil {
		return nil, err
	}
	base := location
	if root.URLBaseStr != "" {
		base, err = url.Parse(root.URLBaseStr)
		if err != nil {
			return nil, err
		}
	}
	root.SetURLBase(base)
	return &root, nil
}

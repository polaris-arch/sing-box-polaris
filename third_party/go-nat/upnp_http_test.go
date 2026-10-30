package nat

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/koron/go-ssdp"
)

func TestUPNPHostnameDeviceAddressUsesCapturedGenerationOnce(t *testing.T) {
	location, _ := url.Parse("http://localhost:0/root.xml")
	client := &mappingTestUPNP{}
	var generations []NAT
	for _, last := range []byte{2, 3} {
		calls := 0
		ctx := upnpHTTPTestContext(context.Background(), upnpHTTPTestTransport(func(*http.Request) (*http.Response, error) {
			t.Error("metadata lookup performed HTTP")
			return nil, errors.New("unexpected HTTP")
		}))
		ctx = context.WithValue(ctx, discoveryResolverKey{}, func(ctx context.Context, host string) ([]net.IP, error) {
			calls++
			if host != "localhost" {
				t.Error("wrong device hostname")
			}
			return []net.IP{net.IPv4(127, 0, 0, last)}, nil
		})
		root := &goupnp.RootDevice{URLBase: *location}
		u, err := newUPNPNAT(ctx, client, "fixture", root)
		if err != nil {
			t.Fatal(err)
		}
		// A later URL mutation and metadata calls cannot resolve another graph.
		root.URLBase.Host = "localhost:9"
		for i := 0; i < 2; i++ {
			address, err := u.GetDeviceAddress()
			if err != nil || !address.Equal(net.IPv4(127, 0, 0, last)) {
				t.Fatal("device metadata used global DNS or new generation", address, err)
			}
			address[0] = 192
		}
		if calls != 1 {
			t.Fatal("device DNS not captured once", calls)
		}
		generations = append(generations, u)
	}
	discovered := make(chan NAT, 2)
	for _, u := range generations {
		discovered <- u
	}
	close(discovered)
	selected, err := selectGateway(context.Background(), discovered, func() (net.IP, error) { return net.IPv4(127, 0, 0, 3), nil })
	if err != nil || selected != generations[1] {
		t.Fatal("selection lost captured device identity", err)
	}
	ctx := upnpHTTPTestContext(context.Background(), upnpHTTPTestTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") }))
	if _, err := newUPNPNAT(ctx, client, "fixture", &goupnp.RootDevice{URLBase: *location}); err == nil {
		t.Fatal("missing captured resolver fell back to process DNS")
	}
}

func TestUPNPDeviceResolverCancellationJoinsBeforeDiscardingLateAddress(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	ctx := upnpHTTPTestContext(parent, upnpHTTPTestTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") }))
	ctx = context.WithValue(ctx, discoveryResolverKey{}, func(context.Context, string) ([]net.IP, error) {
		close(entered)
		<-release
		return []net.IP{net.IPv4(127, 0, 0, 2)}, nil
	})
	location, _ := url.Parse("http://localhost:0/")
	go func() {
		gateway, err := newUPNPNAT(ctx, &mappingTestUPNP{}, "fixture", &goupnp.RootDevice{URLBase: *location})
		if gateway != nil {
			t.Error("late canceled address published")
		}
		done <- err
	}()
	awaitDiscovery(t, entered)
	cancel()
	select {
	case <-done:
		t.Fatal("resolver was detached on cancellation")
	default:
	}
	finish()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("canceled device resolution became success", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("device resolver not joined")
	}
}

func TestUPNPGeneratedSOAPRejectionAndTerminalAbsence(t *testing.T) {
	for _, mode := range []string{"add724", "add725", "query714", "delete714", "delete606", "delete-unknown"} {
		t.Run(mode, func(t *testing.T) {
			adds, queries, deletes := 0, 0, 0
			var external uint16
			fault := func(code int) string {
				return `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>` + strconv.Itoa(code) + `</errorCode><errorDescription>fixture rejection</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`
			}
			response := func(action, fields string) string {
				return `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:` + action + `Response xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">` + fields + `</u:` + action + `Response></s:Body></s:Envelope>`
			}
			ctx := upnpHTTPTestContext(context.Background(), upnpHTTPTestTransport(func(r *http.Request) (*http.Response, error) {
				body, status := upnpHTTPTestXML, 200
				if r.Method == http.MethodPost {
					action := upnpHTTPTestAction(t, r)
					if action.RemoteHost != "" || action.Protocol != "UDP" || action.ExternalPort == 0 {
						t.Error("mapping action changed its remote key", action)
					}
					if action.XMLName.Local != "AddPortMapping" && action.ExternalPort != external {
						t.Error("query/Delete used a different acknowledged mapping", action.ExternalPort, external)
					}
					switch action.XMLName.Local {
					case "AddPortMapping":
						adds++
						external = action.ExternalPort
						if action.InternalPort != 4242 || action.InternalClient != "127.0.0.1" || action.Enabled != "1" || action.LeaseDuration != 60 {
							t.Error("generated Add changed its actual mapping parameters", action)
						}
						body = response("AddPortMapping", "")
						if mode == "add724" {
							body, status = fault(724), 500
						}
						if mode == "add725" {
							body, status = fault(725), 500
						}
					case "GetSpecificPortMappingEntry":
						queries++
						body = response("GetSpecificPortMappingEntry", `<NewInternalPort>4242</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>fixture</NewPortMappingDescription><NewLeaseDuration>60</NewLeaseDuration>`)
						if mode == "query714" {
							body, status = fault(714), 500
						}
					case "DeletePortMapping":
						deletes++
						body = response("DeletePortMapping", "")
						if mode == "delete714" {
							body, status = fault(714), 500
						}
						if mode == "delete606" {
							body, status = fault(606), 500
						}
						if mode == "delete-unknown" {
							return nil, errors.New("SOAP reply lost")
						}
					default:
						t.Error("unexpected SOAP action", action)
					}
				}
				return &http.Response{StatusCode: status, ContentLength: int64(len(body)), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			}))
			location, _ := url.Parse("http://127.0.0.1:0/root.xml")
			root, err := upnpDeviceByURL(ctx, location)
			if err != nil {
				t.Fatal(err)
			}
			var u *upnp_NAT
			root.Device.VisitServices(func(service *goupnp.Service) {
				client := &internetgateway1.WANIPConnection1{ServiceClient: goupnp.ServiceClient{SOAPClient: upnpSOAPClient(ctx, service), RootDevice: root, Service: service}}
				u, err = newUPNPNAT(ctx, client, "generated SOAP", root)
			})
			if err != nil || u == nil {
				t.Fatal("generated mapper missing", err)
			}
			var gateway NAT = u
			_, err = gateway.AddPortMapping(ctx, "udp", 4242, "fixture", time.Minute)
			rejected := mode == "add724" || mode == "add725"
			if (err != nil) != rejected || adds != 1 {
				t.Fatal("generated SOAP create result", mode, err, adds)
			}
			err = gateway.DeletePortMapping(ctx, "udp", 4242)
			resolved := mode != "delete606" && mode != "delete-unknown"
			if (err == nil) != resolved || (len(u.ports) == 0) != resolved {
				t.Fatal("generated terminal result misclassified", mode, err, u.ports)
			}
			if rejected && (queries != 0 || deletes != 0) {
				t.Fatal("rejected Add acquired destructive cleanup", queries, deletes)
			}
			if mode == "query714" && deletes != 0 {
				t.Fatal("confirmed absence caused a Delete")
			}
		})
	}
}

type upnpHTTPTestTransport func(*http.Request) (*http.Response, error)

type upnpHTTPTestSOAPAction struct {
	XMLName        xml.Name
	RemoteHost     string `xml:"NewRemoteHost"`
	ExternalPort   uint16 `xml:"NewExternalPort"`
	Protocol       string `xml:"NewProtocol"`
	InternalPort   uint16 `xml:"NewInternalPort"`
	InternalClient string `xml:"NewInternalClient"`
	Enabled        string `xml:"NewEnabled"`
	LeaseDuration  uint32 `xml:"NewLeaseDuration"`
}

// A private RoundTripper receives goupnp's raw uppercase header map, before
// net/http's wire parser canonicalizes names. Validate that real header and
// the generated request XML agree; never substitute a fake native SOAP result.
func upnpHTTPTestAction(t *testing.T, r *http.Request) upnpHTTPTestSOAPAction {
	t.Helper()
	var envelope struct {
		XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
		Body    struct {
			Actions []upnpHTTPTestSOAPAction `xml:",any"`
		} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	}
	var values []string
	for key, header := range r.Header {
		if strings.EqualFold(key, "SOAPAction") {
			values = append(values, header...)
		}
	}
	defer r.Body.Close()
	if err := xml.NewDecoder(r.Body).Decode(&envelope); err != nil || len(envelope.Body.Actions) != 1 {
		t.Error("invalid generated SOAP request envelope", err)
		return upnpHTTPTestSOAPAction{}
	}
	action := envelope.Body.Actions[0]
	if r.Method != http.MethodPost || r.URL.Path != "/control" || action.XMLName.Space != "urn:schemas-upnp-org:service:WANIPConnection:1" ||
		len(values) != 1 || values[0] != `"`+action.XMLName.Space+"#"+action.XMLName.Local+`"` {
		t.Error("generated SOAP header/body action or selected endpoint disagree", values, action.XMLName, r.URL)
	}
	return action
}

func (f upnpHTTPTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type upnpHTTPTestBody struct {
	io.Reader
	close func() error
}

func (b *upnpHTTPTestBody) Close() error { return b.close() }

func upnpHTTPTestContext(ctx context.Context, transport http.RoundTripper) context.Context {
	return context.WithValue(ctx, discoveryHTTPClientKey{}, &http.Client{Transport: transport})
}

const upnpHTTPTestXML = `<root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/control</controlURL><SCPDURL>/description</SCPDURL><eventSubURL>/event</eventSubURL></service></serviceList></device></root>`

func TestUPNPCapturedHTTPServesXMLAndSOAPWithoutDefaultTransport(t *testing.T) {
	var requests, closed atomic.Int32
	ctx := upnpHTTPTestContext(context.Background(), upnpHTTPTestTransport(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		body := upnpHTTPTestXML
		switch r.Method {
		case http.MethodGet:
			if r.URL.Path != "/root.xml" {
				t.Error("XML URL changed")
			}
		case http.MethodPost:
			if upnpHTTPTestAction(t, r).XMLName.Local != "GetNATRSIPStatus" {
				t.Error("SOAP request escaped the selected service")
			}
			body = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetNATRSIPStatusResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRSIPAvailable>0</NewRSIPAvailable><NewNATEnabled>1</NewNATEnabled></u:GetNATRSIPStatusResponse></s:Body></s:Envelope>`
		default:
			t.Error("unexpected native HTTP operation")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &upnpHTTPTestBody{Reader: strings.NewReader(body), close: func() error { closed.Add(1); return nil }}}, nil
	}))
	// No listener exists here. Only the supplied transport can produce the XML
	// and SOAP responses; an accidental global transport cannot pass this case.
	location, _ := url.Parse("http://127.0.0.1:0/root.xml")
	root, err := upnpDeviceByURL(ctx, location)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	root.Device.VisitServices(func(service *goupnp.Service) {
		count++
		client := &internetgateway1.WANIPConnection1{ServiceClient: goupnp.ServiceClient{SOAPClient: upnpSOAPClient(ctx, service), RootDevice: root, Service: service}}
		_, enabled, err := client.GetNATRSIPStatusCtx(ctx)
		if err != nil || !enabled {
			t.Error("captured SOAP response lost", err)
		}
	})
	if count != 1 || requests.Load() != 2 || closed.Load() != 2 {
		t.Fatal("XML/SOAP request or body escaped its captured client", count, requests.Load(), closed.Load())
	}
}

func TestUPNPXMLCancellationJoinsLateBodyBeforeReturning(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, closing, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	ctx := upnpHTTPTestContext(parent, upnpHTTPTestTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return &http.Response{StatusCode: 200, Body: &upnpHTTPTestBody{Reader: strings.NewReader(upnpHTTPTestXML), close: func() error { close(closing); <-release; return nil }}}, nil
	}))
	location, _ := url.Parse("http://127.0.0.1:0/root.xml")
	done := make(chan error, 1)
	go func() { _, err := upnpDeviceByURL(ctx, location); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("captured XML transport was not entered")
	}
	cancel()
	select {
	case <-closing:
	case <-time.After(5 * time.Second):
		t.Fatal("late XML body not closed")
	}
	select {
	case <-done:
		t.Fatal("discovery returned before actual body close")
	default:
	}
	finish()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost after actual close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("XML close was not joined")
	}
}

func TestUPNPSOAPCanceledAddressCallJoinsLateBody(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, closing, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	ctx := upnpHTTPTestContext(parent, upnpHTTPTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(upnpHTTPTestXML))}, nil
		}
		if upnpHTTPTestAction(t, r).XMLName.Local != "GetExternalIPAddress" {
			t.Error("address query used another SOAP operation")
		}
		close(entered)
		<-r.Context().Done()
		body := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>192.0.2.3</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`
		return &http.Response{StatusCode: 200, Body: &upnpHTTPTestBody{Reader: strings.NewReader(body), close: func() error { close(closing); <-release; return nil }}}, nil
	}))
	location, _ := url.Parse("http://127.0.0.1:0/root.xml")
	root, err := upnpDeviceByURL(ctx, location)
	if err != nil {
		t.Fatal(err)
	}
	var gateway *upnp_NAT
	root.Device.VisitServices(func(service *goupnp.Service) {
		gateway = &upnp_NAT{c: &internetgateway1.WANIPConnection1{ServiceClient: goupnp.ServiceClient{SOAPClient: upnpSOAPClient(ctx, service), RootDevice: root, Service: service}}}
	})
	if gateway == nil {
		t.Fatal("fixture has no native SOAP gateway")
	}
	done := make(chan error, 1)
	go func() { _, err := gateway.GetExternalAddressContext(ctx); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("SOAP did not use the captured transport")
	}
	cancel()
	select {
	case <-closing:
	case <-time.After(5 * time.Second):
		t.Fatal("late SOAP body was not closed")
	}
	select {
	case <-done:
		t.Fatal("address call certified unfinished SOAP cleanup")
	default:
	}
	finish()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("late SOAP success replaced canceled address operation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SOAP body join did not finish")
	}
}

func TestUPNPCapturedDiscoveryJoinsEverySSDPRequestBeforeCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active atomic.Int32
	entered, release := make(chan struct{}, 3), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	ctx := upnpHTTPTestContext(parent, upnpHTTPTestTransport(func(*http.Request) (*http.Response, error) {
		t.Error("canceled search published a device request")
		return nil, errors.New("unexpected XML")
	}))
	done := make(chan error, 1)
	go func() {
		_, err := discoverUPNPDevicesWithSearch(ctx, internetgateway1.URN_WANConnectionDevice_1, func(target string, wait int, local string) ([]ssdp.Service, error) {
			if target != internetgateway1.URN_WANConnectionDevice_1 || wait != 2 || local != "" {
				t.Error("native discovery target changed")
			}
			active.Add(1)
			defer active.Add(-1)
			entered <- struct{}{}
			<-release
			return []ssdp.Service{{USN: "late", Location: "http://127.0.0.1:0/root.xml"}}, nil
		})
		done <- err
	}()
	for i := 0; i < 3; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("discovery request not owned")
		}
	}
	cancel()
	select {
	case <-done:
		t.Fatal("cancellation certified unfinished SSDP calls")
	default:
	}
	finish()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || active.Load() != 0 {
			t.Fatal("discovery request join lost", err, active.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSDP join did not finish")
	}
}

func TestNATCallerHTTPEntryRejectsImplicitDefaultAndCanceledWork(t *testing.T) {
	for _, client := range []*http.Client{nil, {}} {
		if gateway, err := DiscoverGatewayWithHTTPClient(context.Background(), client); gateway != nil || err == nil {
			t.Fatal("implicit global transport accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: upnpHTTPTestTransport(func(*http.Request) (*http.Response, error) {
		t.Error("pre-canceled discovery performed HTTP")
		return nil, errors.New("unexpected HTTP")
	})}
	if gateway, err := DiscoverGatewayWithHTTPClient(ctx, client); gateway != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled discovery escaped", err)
	}
}

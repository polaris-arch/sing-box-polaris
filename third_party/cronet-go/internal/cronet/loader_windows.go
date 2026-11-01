//go:build with_purego && windows

package cronet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/windows"
)

const cronetLibraryPathEnv = "POLARIS_CRONET_LIBRARY_PATH"
const cronetLibrarySearchFlags = windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | windows.LOAD_LIBRARY_SEARCH_SYSTEM32

var processWindowsLibrary windowsLibraryLoader

// windowsLibraryLoader owns one immutable module selection for its lifetime.
// Dependencies belong to each invocation/instance, never to mutable test hooks.
// A successfully registered module stays loaded while its function pointers live.
type windowsLibraryLoader struct {
	once     sync.Once
	err      error
	handle   uintptr
	path     string
	explicit bool
}

type windowsLibraryOps struct {
	lookupEnv func(string) (string, bool)
	discover  func() string
	load      func(string, uintptr) (uintptr, error)
	free      func(uintptr) error
	register  func(uintptr) error
}

func LoadLibrary(path string) error {
	return processWindowsLibrary.load(path, windowsLibraryOps{
		lookupEnv: os.LookupEnv,
		discover:  findLibrary,
		load:      loadWindowsLibrary,
		free:      freeWindowsLibrary,
		register:  registerWindowsLibrarySymbols,
	})
}

func ensureLoaded() {
	if err := LoadLibrary(""); err != nil {
		panic(err)
	}
}

func loadWindowsLibrary(path string, flags uintptr) (uintptr, error) {
	handle, err := windows.LoadLibraryEx(path, 0, flags)
	return uintptr(handle), err
}

func freeWindowsLibrary(handle uintptr) error {
	return windows.FreeLibrary(windows.Handle(handle))
}

func (loader *windowsLibraryLoader) load(request string, ops windowsLibraryOps) error {
	selector, explicit := ops.lookupEnv(cronetLibraryPathEnv)
	loader.once.Do(func() {
		loader.initialize(request, selector, explicit, ops)
	})
	if loader.err != nil {
		return loader.err
	}
	// Warm calls perform no file metadata lookup or discovery. Environment changes
	// cannot replace an already selected module or silently switch loading modes.
	if explicit != loader.explicit {
		return errors.New("cronet: library selector mode changed after initial load")
	}
	if explicit {
		selected, err := explicitWindowsLibraryPath(selector)
		if err != nil {
			return fmt.Errorf("cronet: invalid %s: %w", cronetLibraryPathEnv, err)
		}
		if !sameWindowsLibraryPath(selected, loader.path) {
			return errors.New("cronet: library selector changed after initial load")
		}
	}
	if request != "" {
		requested, err := requestedWindowsLibraryPath(request, explicit)
		if err != nil {
			return err
		}
		if !sameWindowsLibraryPath(requested, loader.path) {
			return errors.New("cronet: requested library conflicts with the selected module")
		}
	}
	return nil
}

func (loader *windowsLibraryLoader) initialize(request, selector string, explicit bool, ops windowsLibraryOps) {
	var handle uintptr
	defer func() {
		if recovered := recover(); recovered != nil {
			loader.err = fmt.Errorf("cronet: library initialization panicked: %v", recovered)
		}
		if handle != 0 && loader.handle == 0 {
			if err := ops.free(handle); err != nil {
				loader.err = errors.Join(loader.err, fmt.Errorf("cronet: failed to release rejected library: %w", err))
			}
		}
	}()
	path, err := selectWindowsLibrary(request, selector, explicit, ops.discover)
	if err != nil {
		loader.err = err
		return
	}
	loader.path, loader.explicit = path, explicit
	handle, err = ops.load(path, cronetLibrarySearchFlags)
	if err != nil {
		loader.err = fmt.Errorf("cronet: failed to load selected library %s: %w", path, err)
		return
	}
	if handle == 0 {
		loader.err = errors.New("cronet: loading selected library returned an empty handle")
		return
	}
	if err := ops.register(handle); err != nil {
		loader.err = fmt.Errorf("cronet: failed to register selected library: %w", err)
		return
	}
	// Publish only a completely registered module. No unload is safe after this
	// point: the bindings refer to this exact module for the process lifetime.
	loader.handle = handle
}

func selectWindowsLibrary(request, selector string, explicit bool, discover func() string) (string, error) {
	var path string
	var err error
	if explicit {
		// The selector is a choice, not provenance/hash admission or an object lease.
		// The App must supply and protect its already admitted private DLL cohort.
		path, err = explicitWindowsLibraryPath(selector)
		if err != nil {
			return "", fmt.Errorf("cronet: invalid %s: %w", cronetLibraryPathEnv, err)
		}
		if request != "" {
			requested, requestErr := requestedWindowsLibraryPath(request, true)
			if requestErr != nil {
				return "", requestErr
			}
			if !sameWindowsLibraryPath(path, requested) {
				return "", errors.New("cronet: requested library conflicts with explicit selector")
			}
		}
	} else {
		// Compatibility discovery is exclusively for standalone callers without an
		// explicit selector. It never becomes a fallback for trusted App selection.
		if request == "" {
			request = discover()
		}
		if request == "" {
			return "", errors.New("cronet: library not found in executable directory or PATH")
		}
		path, err = requestedWindowsLibraryPath(request, false)
		if err != nil {
			return "", err
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cronet: selected library is unavailable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("cronet: selected library is not a regular file")
	}
	return path, nil
}

func absoluteWindowsLibraryPath(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, '\x00') || !filepath.IsAbs(path) {
		return "", errors.New("an absolute, nonempty library path without NUL is required")
	}
	return filepath.Clean(path), nil
}

func explicitWindowsLibraryPath(path string) (string, error) {
	absolute, err := absoluteWindowsLibraryPath(path)
	if err != nil {
		return "", err
	}
	// LoadLibraryExW may append .dll to an extensionless module name. Reject
	// that spelling before Stat or native loading so the explicit choice cannot
	// name one file for validation and another file for execution. Standalone
	// callers retain their separate compatibility path below.
	if filepath.Ext(absolute) == "" {
		return "", errors.New("an explicit library filename extension is required to prevent implicit .dll completion")
	}
	return absolute, nil
}

func requestedWindowsLibraryPath(path string, explicit bool) (string, error) {
	if explicit {
		selected, err := explicitWindowsLibraryPath(path)
		if err != nil {
			return "", fmt.Errorf("cronet: invalid requested library path: %w", err)
		}
		return selected, nil
	}
	if strings.ContainsRune(path, '\x00') {
		return "", errors.New("cronet: requested library path contains NUL")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("cronet: failed to make library path absolute: %w", err)
	}
	return absoluteWindowsLibraryPath(absolute)
}

func sameWindowsLibraryPath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func findLibrary() string {
	executablePath, err := os.Executable()
	var searchPaths []string
	if err == nil {
		searchPaths = append(searchPaths, filepath.Dir(executablePath))
	}
	if pathEnv := os.Getenv("PATH"); pathEnv != "" {
		searchPaths = append(searchPaths, filepath.SplitList(pathEnv)...)
	}
	for _, directory := range searchPaths {
		path := filepath.Join(directory, "libcronet.dll")
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

// Retain the adapters used by the architecture-specific helper source. Initial
// module loading uses the complete transactional registry below, including its
// two floating-point entries, rather than publishing partial symbol bindings.
func lookupSymbol(name string) (uintptr, error) {
	if processWindowsLibrary.handle == 0 {
		return 0, errors.New("cronet: library not loaded")
	}
	return lookupWindowsLibrarySymbol(processWindowsLibrary.handle, name)
}

func lookupWindowsLibrarySymbol(handle uintptr, name string) (uintptr, error) {
	address, err := windows.GetProcAddress(windows.Handle(handle), name)
	if err != nil {
		return 0, fmt.Errorf("cronet: symbol %s not found: %w", name, err)
	}
	return address, nil
}

func registerFunc(target interface{}, name string) error {
	address, err := lookupSymbol(name)
	if err != nil {
		return err
	}
	purego.RegisterFunc(target, address)
	return nil
}

type windowsLibrarySymbol struct {
	name   string
	target interface{}
}

func registerWindowsLibrarySymbols(handle uintptr) error {
	return bindWindowsLibrarySymbols(handle, windowsLibrarySymbols(), lookupWindowsLibrarySymbol, purego.RegisterFunc)
}

// Resolve every export before publishing any binding. If purego rejects a
// signature, restore all function variables before the caller releases the DLL.
func bindWindowsLibrarySymbols(handle uintptr, symbols []windowsLibrarySymbol, lookup func(uintptr, string) (uintptr, error), bind func(interface{}, uintptr)) (err error) {
	if handle == 0 {
		return errors.New("cronet: cannot register an empty library handle")
	}
	addresses := make([]uintptr, len(symbols))
	targets := make([]reflect.Value, len(symbols))
	previous := make([]reflect.Value, len(symbols))
	for i, symbol := range symbols {
		target := reflect.ValueOf(symbol.target)
		if target.Kind() != reflect.Ptr || target.IsNil() || target.Elem().Kind() != reflect.Func || !target.Elem().CanSet() {
			return fmt.Errorf("cronet: invalid function target for symbol %s", symbol.name)
		}
		targets[i] = target.Elem()
		previous[i] = reflect.New(targets[i].Type()).Elem()
		previous[i].Set(targets[i])
		addresses[i], err = lookup(handle, symbol.name)
		if err != nil {
			return err
		}
		if addresses[i] == 0 {
			return fmt.Errorf("cronet: symbol %s resolved to an empty address", symbol.name)
		}
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			for i := range targets {
				targets[i].Set(previous[i])
			}
			err = fmt.Errorf("cronet: symbol binding failed: %v", recovered)
		}
	}()
	for i := range symbols {
		bind(symbols[i].target, addresses[i])
	}
	return nil
}

func windowsLibrarySymbols() []windowsLibrarySymbol {
	return []windowsLibrarySymbol{

		// Buffer
		{"Cronet_Buffer_Create", &cronetBufferCreate},
		{"Cronet_Buffer_Destroy", &cronetBufferDestroy},
		{"Cronet_Buffer_SetClientContext", &cronetBufferSetClientContext},
		{"Cronet_Buffer_GetClientContext", &cronetBufferGetClientContext},
		{"Cronet_Buffer_InitWithDataAndCallback", &cronetBufferInitWithDataAndCallback},
		{"Cronet_Buffer_InitWithAlloc", &cronetBufferInitWithAlloc},
		{"Cronet_Buffer_GetSize", &cronetBufferGetSize},
		{"Cronet_Buffer_GetData", &cronetBufferGetData},

		// BufferCallback
		{"Cronet_BufferCallback_Destroy", &cronetBufferCallbackDestroy},
		{"Cronet_BufferCallback_SetClientContext", &cronetBufferCallbackSetClientContext},
		{"Cronet_BufferCallback_GetClientContext", &cronetBufferCallbackGetClientContext},
		{"Cronet_BufferCallback_CreateWith", &cronetBufferCallbackCreateWith},

		// Runnable
		{"Cronet_Runnable_Destroy", &cronetRunnableDestroy},
		{"Cronet_Runnable_SetClientContext", &cronetRunnableSetClientContext},
		{"Cronet_Runnable_GetClientContext", &cronetRunnableGetClientContext},
		{"Cronet_Runnable_Run", &cronetRunnableRun},
		{"Cronet_Runnable_CreateWith", &cronetRunnableCreateWith},

		// Executor
		{"Cronet_Executor_Destroy", &cronetExecutorDestroy},
		{"Cronet_Executor_SetClientContext", &cronetExecutorSetClientContext},
		{"Cronet_Executor_GetClientContext", &cronetExecutorGetClientContext},
		{"Cronet_Executor_Execute", &cronetExecutorExecute},
		{"Cronet_Executor_CreateWith", &cronetExecutorCreateWith},

		// Engine
		{"Cronet_Engine_Create", &cronetEngineCreate},
		{"Cronet_Engine_Destroy", &cronetEngineDestroy},
		{"Cronet_Engine_SetClientContext", &cronetEngineSetClientContext},
		{"Cronet_Engine_GetClientContext", &cronetEngineGetClientContext},
		{"Cronet_Engine_StartWithParams", &cronetEngineStartWithParams},
		{"Cronet_Engine_StartNetLogToFile", &cronetEngineStartNetLogToFile},
		{"Cronet_Engine_StopNetLog", &cronetEngineStopNetLog},
		{"Cronet_Engine_Shutdown", &cronetEngineShutdown},
		{"Cronet_Engine_GetVersionString", &cronetEngineGetVersionString},
		{"Cronet_Engine_GetDefaultUserAgent", &cronetEngineGetDefaultUserAgent},
		{"Cronet_Engine_AddRequestFinishedListener", &cronetEngineAddRequestFinishedListener},
		{"Cronet_Engine_RemoveRequestFinishedListener", &cronetEngineRemoveRequestFinishedListener},
		{"Cronet_Engine_GetStreamEngine", &cronetEngineGetStreamEngine},
		{"Cronet_Engine_SetMockCertVerifierForTesting", &cronetEngineSetMockCertVerifierForTesting},
		{"Cronet_Engine_CloseAllConnections", &cronetEngineCloseAllConnections},
		{"Cronet_Engine_SetDialer", &cronetEngineSetDialer},
		{"Cronet_Engine_SetUdpDialer", &cronetEngineSetUdpDialer},

		// EngineParams
		{"Cronet_EngineParams_Create", &cronetEngineParamsCreate},
		{"Cronet_EngineParams_Destroy", &cronetEngineParamsDestroy},
		{"Cronet_EngineParams_enable_check_result_set", &cronetEngineParamsEnableCheckResultSet},
		{"Cronet_EngineParams_user_agent_set", &cronetEngineParamsUserAgentSet},
		{"Cronet_EngineParams_accept_language_set", &cronetEngineParamsAcceptLanguageSet},
		{"Cronet_EngineParams_storage_path_set", &cronetEngineParamsStoragePathSet},
		{"Cronet_EngineParams_enable_quic_set", &cronetEngineParamsEnableQuicSet},
		{"Cronet_EngineParams_enable_http2_set", &cronetEngineParamsEnableHttp2Set},
		{"Cronet_EngineParams_enable_brotli_set", &cronetEngineParamsEnableBrotliSet},
		{"Cronet_EngineParams_http_cache_mode_set", &cronetEngineParamsHttpCacheModeSet},
		{"Cronet_EngineParams_http_cache_max_size_set", &cronetEngineParamsHttpCacheMaxSizeSet},
		{"Cronet_EngineParams_quic_hints_add", &cronetEngineParamsQuicHintsAdd},
		{"Cronet_EngineParams_public_key_pins_add", &cronetEngineParamsPublicKeyPinsAdd},
		{"Cronet_EngineParams_enable_public_key_pinning_bypass_for_local_trust_anchors_set", &cronetEngineParamsEnablePublicKeyPinningBypassForLocalTrustAnchorsSet},
		{"Cronet_EngineParams_experimental_options_set", &cronetEngineParamsExperimentalOptionsSet},
		{"Cronet_EngineParams_enable_check_result_get", &cronetEngineParamsEnableCheckResultGet},
		{"Cronet_EngineParams_user_agent_get", &cronetEngineParamsUserAgentGet},
		{"Cronet_EngineParams_accept_language_get", &cronetEngineParamsAcceptLanguageGet},
		{"Cronet_EngineParams_storage_path_get", &cronetEngineParamsStoragePathGet},
		{"Cronet_EngineParams_enable_quic_get", &cronetEngineParamsEnableQuicGet},
		{"Cronet_EngineParams_enable_http2_get", &cronetEngineParamsEnableHttp2Get},
		{"Cronet_EngineParams_enable_brotli_get", &cronetEngineParamsEnableBrotliGet},
		{"Cronet_EngineParams_http_cache_mode_get", &cronetEngineParamsHttpCacheModeGet},
		{"Cronet_EngineParams_http_cache_max_size_get", &cronetEngineParamsHttpCacheMaxSizeGet},
		{"Cronet_EngineParams_quic_hints_size", &cronetEngineParamsQuicHintsSize},
		{"Cronet_EngineParams_quic_hints_at", &cronetEngineParamsQuicHintsAt},
		{"Cronet_EngineParams_quic_hints_clear", &cronetEngineParamsQuicHintsClear},
		{"Cronet_EngineParams_public_key_pins_size", &cronetEngineParamsPublicKeyPinsSize},
		{"Cronet_EngineParams_public_key_pins_at", &cronetEngineParamsPublicKeyPinsAt},
		{"Cronet_EngineParams_public_key_pins_clear", &cronetEngineParamsPublicKeyPinsClear},
		{"Cronet_EngineParams_enable_public_key_pinning_bypass_for_local_trust_anchors_get", &cronetEngineParamsEnablePublicKeyPinningBypassForLocalTrustAnchorsGet},
		{"Cronet_EngineParams_experimental_options_get", &cronetEngineParamsExperimentalOptionsGet},

		// UrlRequest
		{"Cronet_UrlRequest_Create", &cronetUrlRequestCreate},
		{"Cronet_UrlRequest_Destroy", &cronetUrlRequestDestroy},
		{"Cronet_UrlRequest_SetClientContext", &cronetUrlRequestSetClientContext},
		{"Cronet_UrlRequest_GetClientContext", &cronetUrlRequestGetClientContext},
		{"Cronet_UrlRequest_InitWithParams", &cronetUrlRequestInitWithParams},
		{"Cronet_UrlRequest_Start", &cronetUrlRequestStart},
		{"Cronet_UrlRequest_FollowRedirect", &cronetUrlRequestFollowRedirect},
		{"Cronet_UrlRequest_Read", &cronetUrlRequestRead},
		{"Cronet_UrlRequest_Cancel", &cronetUrlRequestCancel},
		{"Cronet_UrlRequest_IsDone", &cronetUrlRequestIsDone},
		{"Cronet_UrlRequest_GetStatus", &cronetUrlRequestGetStatus},

		// UrlRequestParams
		{"Cronet_UrlRequestParams_Create", &cronetUrlRequestParamsCreate},
		{"Cronet_UrlRequestParams_Destroy", &cronetUrlRequestParamsDestroy},
		{"Cronet_UrlRequestParams_http_method_set", &cronetUrlRequestParamsHttpMethodSet},
		{"Cronet_UrlRequestParams_request_headers_add", &cronetUrlRequestParamsRequestHeadersAdd},
		{"Cronet_UrlRequestParams_disable_cache_set", &cronetUrlRequestParamsDisableCacheSet},
		{"Cronet_UrlRequestParams_priority_set", &cronetUrlRequestParamsPrioritySet},
		{"Cronet_UrlRequestParams_upload_data_provider_set", &cronetUrlRequestParamsUploadDataProviderSet},
		{"Cronet_UrlRequestParams_upload_data_provider_executor_set", &cronetUrlRequestParamsUploadDataProviderExecutorSet},
		{"Cronet_UrlRequestParams_allow_direct_executor_set", &cronetUrlRequestParamsAllowDirectExecutorSet},
		{"Cronet_UrlRequestParams_annotations_add", &cronetUrlRequestParamsAnnotationsAdd},
		{"Cronet_UrlRequestParams_request_finished_listener_set", &cronetUrlRequestParamsRequestFinishedListenerSet},
		{"Cronet_UrlRequestParams_request_finished_executor_set", &cronetUrlRequestParamsRequestFinishedExecutorSet},
		{"Cronet_UrlRequestParams_idempotency_set", &cronetUrlRequestParamsIdempotencySet},
		{"Cronet_UrlRequestParams_http_method_get", &cronetUrlRequestParamsHttpMethodGet},
		{"Cronet_UrlRequestParams_request_headers_size", &cronetUrlRequestParamsRequestHeadersSize},
		{"Cronet_UrlRequestParams_request_headers_at", &cronetUrlRequestParamsRequestHeadersAt},
		{"Cronet_UrlRequestParams_request_headers_clear", &cronetUrlRequestParamsRequestHeadersClear},
		{"Cronet_UrlRequestParams_disable_cache_get", &cronetUrlRequestParamsDisableCacheGet},
		{"Cronet_UrlRequestParams_priority_get", &cronetUrlRequestParamsPriorityGet},
		{"Cronet_UrlRequestParams_upload_data_provider_get", &cronetUrlRequestParamsUploadDataProviderGet},
		{"Cronet_UrlRequestParams_upload_data_provider_executor_get", &cronetUrlRequestParamsUploadDataProviderExecutorGet},
		{"Cronet_UrlRequestParams_allow_direct_executor_get", &cronetUrlRequestParamsAllowDirectExecutorGet},
		{"Cronet_UrlRequestParams_annotations_size", &cronetUrlRequestParamsAnnotationsSize},
		{"Cronet_UrlRequestParams_annotations_at", &cronetUrlRequestParamsAnnotationsAt},
		{"Cronet_UrlRequestParams_annotations_clear", &cronetUrlRequestParamsAnnotationsClear},
		{"Cronet_UrlRequestParams_request_finished_listener_get", &cronetUrlRequestParamsRequestFinishedListenerGet},
		{"Cronet_UrlRequestParams_request_finished_executor_get", &cronetUrlRequestParamsRequestFinishedExecutorGet},
		{"Cronet_UrlRequestParams_idempotency_get", &cronetUrlRequestParamsIdempotencyGet},

		// UrlRequestCallback
		{"Cronet_UrlRequestCallback_Destroy", &cronetUrlRequestCallbackDestroy},
		{"Cronet_UrlRequestCallback_SetClientContext", &cronetUrlRequestCallbackSetClientContext},
		{"Cronet_UrlRequestCallback_GetClientContext", &cronetUrlRequestCallbackGetClientContext},
		{"Cronet_UrlRequestCallback_CreateWith", &cronetUrlRequestCallbackCreateWith},

		// UrlRequestStatusListener
		{"Cronet_UrlRequestStatusListener_Destroy", &cronetUrlRequestStatusListenerDestroy},
		{"Cronet_UrlRequestStatusListener_SetClientContext", &cronetUrlRequestStatusListenerSetClientContext},
		{"Cronet_UrlRequestStatusListener_GetClientContext", &cronetUrlRequestStatusListenerGetClientContext},
		{"Cronet_UrlRequestStatusListener_CreateWith", &cronetUrlRequestStatusListenerCreateWith},

		// UploadDataProvider
		{"Cronet_UploadDataProvider_Destroy", &cronetUploadDataProviderDestroy},
		{"Cronet_UploadDataProvider_SetClientContext", &cronetUploadDataProviderSetClientContext},
		{"Cronet_UploadDataProvider_GetClientContext", &cronetUploadDataProviderGetClientContext},
		{"Cronet_UploadDataProvider_CreateWith", &cronetUploadDataProviderCreateWith},

		// UploadDataSink
		{"Cronet_UploadDataSink_Destroy", &cronetUploadDataSinkDestroy},
		{"Cronet_UploadDataSink_SetClientContext", &cronetUploadDataSinkSetClientContext},
		{"Cronet_UploadDataSink_GetClientContext", &cronetUploadDataSinkGetClientContext},
		{"Cronet_UploadDataSink_OnReadSucceeded", &cronetUploadDataSinkOnReadSucceeded},
		{"Cronet_UploadDataSink_OnReadError", &cronetUploadDataSinkOnReadError},
		{"Cronet_UploadDataSink_OnRewindSucceeded", &cronetUploadDataSinkOnRewindSucceeded},
		{"Cronet_UploadDataSink_OnRewindError", &cronetUploadDataSinkOnRewindError},

		// UrlResponseInfo
		{"Cronet_UrlResponseInfo_Create", &cronetUrlResponseInfoCreate},
		{"Cronet_UrlResponseInfo_Destroy", &cronetUrlResponseInfoDestroy},
		{"Cronet_UrlResponseInfo_url_set", &cronetUrlResponseInfoUrlSet},
		{"Cronet_UrlResponseInfo_url_chain_add", &cronetUrlResponseInfoUrlChainAdd},
		{"Cronet_UrlResponseInfo_http_status_code_set", &cronetUrlResponseInfoHttpStatusCodeSet},
		{"Cronet_UrlResponseInfo_http_status_text_set", &cronetUrlResponseInfoHttpStatusTextSet},
		{"Cronet_UrlResponseInfo_all_headers_list_add", &cronetUrlResponseInfoAllHeadersListAdd},
		{"Cronet_UrlResponseInfo_was_cached_set", &cronetUrlResponseInfoWasCachedSet},
		{"Cronet_UrlResponseInfo_negotiated_protocol_set", &cronetUrlResponseInfoNegotiatedProtocolSet},
		{"Cronet_UrlResponseInfo_proxy_server_set", &cronetUrlResponseInfoProxyServerSet},
		{"Cronet_UrlResponseInfo_received_byte_count_set", &cronetUrlResponseInfoReceivedByteCountSet},
		{"Cronet_UrlResponseInfo_url_get", &cronetUrlResponseInfoUrlGet},
		{"Cronet_UrlResponseInfo_url_chain_size", &cronetUrlResponseInfoUrlChainSize},
		{"Cronet_UrlResponseInfo_url_chain_at", &cronetUrlResponseInfoUrlChainAt},
		{"Cronet_UrlResponseInfo_url_chain_clear", &cronetUrlResponseInfoUrlChainClear},
		{"Cronet_UrlResponseInfo_http_status_code_get", &cronetUrlResponseInfoHttpStatusCodeGet},
		{"Cronet_UrlResponseInfo_http_status_text_get", &cronetUrlResponseInfoHttpStatusTextGet},
		{"Cronet_UrlResponseInfo_all_headers_list_size", &cronetUrlResponseInfoAllHeadersListSize},
		{"Cronet_UrlResponseInfo_all_headers_list_at", &cronetUrlResponseInfoAllHeadersListAt},
		{"Cronet_UrlResponseInfo_all_headers_list_clear", &cronetUrlResponseInfoAllHeadersListClear},
		{"Cronet_UrlResponseInfo_was_cached_get", &cronetUrlResponseInfoWasCachedGet},
		{"Cronet_UrlResponseInfo_negotiated_protocol_get", &cronetUrlResponseInfoNegotiatedProtocolGet},
		{"Cronet_UrlResponseInfo_proxy_server_get", &cronetUrlResponseInfoProxyServerGet},
		{"Cronet_UrlResponseInfo_received_byte_count_get", &cronetUrlResponseInfoReceivedByteCountGet},

		// Error
		{"Cronet_Error_Create", &cronetErrorCreate},
		{"Cronet_Error_Destroy", &cronetErrorDestroy},
		{"Cronet_Error_error_code_set", &cronetErrorErrorCodeSet},
		{"Cronet_Error_message_set", &cronetErrorMessageSet},
		{"Cronet_Error_internal_error_code_set", &cronetErrorInternalErrorCodeSet},
		{"Cronet_Error_immediately_retryable_set", &cronetErrorImmediatelyRetryableSet},
		{"Cronet_Error_quic_detailed_error_code_set", &cronetErrorQuicDetailedErrorCodeSet},
		{"Cronet_Error_error_code_get", &cronetErrorErrorCodeGet},
		{"Cronet_Error_message_get", &cronetErrorMessageGet},
		{"Cronet_Error_internal_error_code_get", &cronetErrorInternalErrorCodeGet},
		{"Cronet_Error_immediately_retryable_get", &cronetErrorImmediatelyRetryableGet},
		{"Cronet_Error_quic_detailed_error_code_get", &cronetErrorQuicDetailedErrorCodeGet},

		// HttpHeader
		{"Cronet_HttpHeader_Create", &cronetHttpHeaderCreate},
		{"Cronet_HttpHeader_Destroy", &cronetHttpHeaderDestroy},
		{"Cronet_HttpHeader_name_set", &cronetHttpHeaderNameSet},
		{"Cronet_HttpHeader_value_set", &cronetHttpHeaderValueSet},
		{"Cronet_HttpHeader_name_get", &cronetHttpHeaderNameGet},
		{"Cronet_HttpHeader_value_get", &cronetHttpHeaderValueGet},

		// QuicHint
		{"Cronet_QuicHint_Create", &cronetQuicHintCreate},
		{"Cronet_QuicHint_Destroy", &cronetQuicHintDestroy},
		{"Cronet_QuicHint_host_set", &cronetQuicHintHostSet},
		{"Cronet_QuicHint_port_set", &cronetQuicHintPortSet},
		{"Cronet_QuicHint_alternate_port_set", &cronetQuicHintAlternatePortSet},
		{"Cronet_QuicHint_host_get", &cronetQuicHintHostGet},
		{"Cronet_QuicHint_port_get", &cronetQuicHintPortGet},
		{"Cronet_QuicHint_alternate_port_get", &cronetQuicHintAlternatePortGet},

		// PublicKeyPins
		{"Cronet_PublicKeyPins_Create", &cronetPublicKeyPinsCreate},
		{"Cronet_PublicKeyPins_Destroy", &cronetPublicKeyPinsDestroy},
		{"Cronet_PublicKeyPins_host_set", &cronetPublicKeyPinsHostSet},
		{"Cronet_PublicKeyPins_pins_sha256_add", &cronetPublicKeyPinsPinsSha256Add},
		{"Cronet_PublicKeyPins_include_subdomains_set", &cronetPublicKeyPinsIncludeSubdomainsSet},
		{"Cronet_PublicKeyPins_expiration_date_set", &cronetPublicKeyPinsExpirationDateSet},
		{"Cronet_PublicKeyPins_host_get", &cronetPublicKeyPinsHostGet},
		{"Cronet_PublicKeyPins_pins_sha256_size", &cronetPublicKeyPinsPinsSha256Size},
		{"Cronet_PublicKeyPins_pins_sha256_at", &cronetPublicKeyPinsPinsSha256At},
		{"Cronet_PublicKeyPins_pins_sha256_clear", &cronetPublicKeyPinsPinsSha256Clear},
		{"Cronet_PublicKeyPins_include_subdomains_get", &cronetPublicKeyPinsIncludeSubdomainsGet},
		{"Cronet_PublicKeyPins_expiration_date_get", &cronetPublicKeyPinsExpirationDateGet},

		// DateTime
		{"Cronet_DateTime_Create", &cronetDateTimeCreate},
		{"Cronet_DateTime_Destroy", &cronetDateTimeDestroy},
		{"Cronet_DateTime_value_set", &cronetDateTimeValueSet},
		{"Cronet_DateTime_value_get", &cronetDateTimeValueGet},

		// Metrics
		{"Cronet_Metrics_Create", &cronetMetricsCreate},
		{"Cronet_Metrics_Destroy", &cronetMetricsDestroy},
		{"Cronet_Metrics_request_start_set", &cronetMetricsRequestStartSet},
		{"Cronet_Metrics_dns_start_set", &cronetMetricsDnsStartSet},
		{"Cronet_Metrics_dns_end_set", &cronetMetricsDnsEndSet},
		{"Cronet_Metrics_connect_start_set", &cronetMetricsConnectStartSet},
		{"Cronet_Metrics_connect_end_set", &cronetMetricsConnectEndSet},
		{"Cronet_Metrics_ssl_start_set", &cronetMetricsSslStartSet},
		{"Cronet_Metrics_ssl_end_set", &cronetMetricsSslEndSet},
		{"Cronet_Metrics_sending_start_set", &cronetMetricsSendingStartSet},
		{"Cronet_Metrics_sending_end_set", &cronetMetricsSendingEndSet},
		{"Cronet_Metrics_push_start_set", &cronetMetricsPushStartSet},
		{"Cronet_Metrics_push_end_set", &cronetMetricsPushEndSet},
		{"Cronet_Metrics_response_start_set", &cronetMetricsResponseStartSet},
		{"Cronet_Metrics_request_end_set", &cronetMetricsRequestEndSet},
		{"Cronet_Metrics_socket_reused_set", &cronetMetricsSocketReusedSet},
		{"Cronet_Metrics_sent_byte_count_set", &cronetMetricsSentByteCountSet},
		{"Cronet_Metrics_received_byte_count_set", &cronetMetricsReceivedByteCountSet},
		{"Cronet_Metrics_request_start_get", &cronetMetricsRequestStartGet},
		{"Cronet_Metrics_dns_start_get", &cronetMetricsDnsStartGet},
		{"Cronet_Metrics_dns_end_get", &cronetMetricsDnsEndGet},
		{"Cronet_Metrics_connect_start_get", &cronetMetricsConnectStartGet},
		{"Cronet_Metrics_connect_end_get", &cronetMetricsConnectEndGet},
		{"Cronet_Metrics_ssl_start_get", &cronetMetricsSslStartGet},
		{"Cronet_Metrics_ssl_end_get", &cronetMetricsSslEndGet},
		{"Cronet_Metrics_sending_start_get", &cronetMetricsSendingStartGet},
		{"Cronet_Metrics_sending_end_get", &cronetMetricsSendingEndGet},
		{"Cronet_Metrics_push_start_get", &cronetMetricsPushStartGet},
		{"Cronet_Metrics_push_end_get", &cronetMetricsPushEndGet},
		{"Cronet_Metrics_response_start_get", &cronetMetricsResponseStartGet},
		{"Cronet_Metrics_request_end_get", &cronetMetricsRequestEndGet},
		{"Cronet_Metrics_socket_reused_get", &cronetMetricsSocketReusedGet},
		{"Cronet_Metrics_sent_byte_count_get", &cronetMetricsSentByteCountGet},
		{"Cronet_Metrics_received_byte_count_get", &cronetMetricsReceivedByteCountGet},

		// RequestFinishedInfo
		{"Cronet_RequestFinishedInfo_Create", &cronetRequestFinishedInfoCreate},
		{"Cronet_RequestFinishedInfo_Destroy", &cronetRequestFinishedInfoDestroy},
		{"Cronet_RequestFinishedInfo_metrics_set", &cronetRequestFinishedInfoMetricsSet},
		{"Cronet_RequestFinishedInfo_annotations_add", &cronetRequestFinishedInfoAnnotationsAdd},
		{"Cronet_RequestFinishedInfo_finished_reason_set", &cronetRequestFinishedInfoFinishedReasonSet},
		{"Cronet_RequestFinishedInfo_metrics_get", &cronetRequestFinishedInfoMetricsGet},
		{"Cronet_RequestFinishedInfo_annotations_size", &cronetRequestFinishedInfoAnnotationsSize},
		{"Cronet_RequestFinishedInfo_annotations_at", &cronetRequestFinishedInfoAnnotationsAt},
		{"Cronet_RequestFinishedInfo_annotations_clear", &cronetRequestFinishedInfoAnnotationsClear},
		{"Cronet_RequestFinishedInfo_finished_reason_get", &cronetRequestFinishedInfoFinishedReasonGet},

		// RequestFinishedInfoListener
		{"Cronet_RequestFinishedInfoListener_Destroy", &cronetRequestFinishedInfoListenerDestroy},
		{"Cronet_RequestFinishedInfoListener_SetClientContext", &cronetRequestFinishedInfoListenerSetClientContext},
		{"Cronet_RequestFinishedInfoListener_GetClientContext", &cronetRequestFinishedInfoListenerGetClientContext},
		{"Cronet_RequestFinishedInfoListener_CreateWith", &cronetRequestFinishedInfoListenerCreateWith},

		// Custom cert verifier
		{"Cronet_CreateCertVerifierWithRootCerts", &cronetCreateCertVerifierWithRootCerts},

		// BidirectionalStream
		{"bidirectional_stream_create", &bidirectionalStreamCreate},
		{"bidirectional_stream_destroy", &bidirectionalStreamDestroy},
		{"bidirectional_stream_disable_auto_flush", &bidirectionalStreamDisableAutoFlush},
		{"bidirectional_stream_delay_request_headers_until_flush", &bidirectionalStreamDelayRequestHeadersUntilFlush},
		{"bidirectional_stream_start", &bidirectionalStreamStart},
		{"bidirectional_stream_read", &bidirectionalStreamRead},
		{"bidirectional_stream_write", &bidirectionalStreamWrite},
		{"bidirectional_stream_flush", &bidirectionalStreamFlush},
		{"bidirectional_stream_cancel", &bidirectionalStreamCancel},

		// Floating-point entries, formerly registered after all other bindings.
		{"Cronet_EngineParams_network_thread_priority_set", &cronetEngineParamsNetworkThreadPrioritySet},
		{"Cronet_EngineParams_network_thread_priority_get", &cronetEngineParamsNetworkThreadPriorityGet},
	}
}

package healthcheck

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
)

type (
	healthCheck struct {
		prefix         string
		tag            string
		commit         string
		hostname       string
		servicesGuard  sync.RWMutex
		services       map[string]HealthChecker
		serviceTimeout time.Duration
	}

	healthCheckResponse struct {
		Version struct {
			Tag    string `json:"tag"`
			Commit string `json:"commit"`
		} `json:"version"`
		Status   bool                                   `json:"status"`
		Elapsed  time.Duration                          `json:"elapsed"`
		Hostname string                                 `json:"hostname"`
		Checks   map[string]*healthCheckServiceResponse `json:"checks,omitempty"`
		System   struct {
			Version         string `json:"version,omitempty"`
			NumCPU          int    `json:"num_cpu"`
			NumGoroutines   int    `json:"num_goroutines"`
			NumHeapObjects  uint64 `json:"num_heap_objects"`
			TotalAllocBytes uint64 `json:"total_alloc_bytes"`
			AllocBytes      uint64 `json:"alloc_bytes"`
		} `json:"system,omitempty"`
		sync.Mutex
	}

	healthCheckServiceResponse struct {
		Status  bool          `json:"status"`
		Elapsed time.Duration `json:"elapsed"`
		Detail  interface{}   `json:"detail,omitempty"`
		Error   interface{}   `json:"error,omitempty"`
		sync.Mutex
	}
)

var serviceTimeout = 1 * time.Second

// NewHealthCheck create a new health check handler
func NewHealthCheck(appName, tag, commit string) Handler {
	hostname, _ := os.Hostname()
	services := make(map[string]HealthChecker)
	return &healthCheck{
		prefix:         "/" + appName,
		tag:            tag,
		commit:         commit,
		hostname:       hostname,
		services:       services,
		serviceTimeout: serviceTimeout,
	}
}

func (h *healthCheck) RegisterRoutes(router *mux.Router) {
	router.HandleFunc(h.prefix+"/health/check", h.handler).Methods(http.MethodGet)
}

func (h *healthCheck) RegisterService(name string, s HealthChecker) {
	h.servicesGuard.Lock()
	h.services[name] = s
	h.servicesGuard.Unlock()
}

func (h *healthCheck) newResponse() *healthCheckResponse {
	resp := &healthCheckResponse{
		Status:   true,
		Hostname: h.hostname,
		Checks:   make(map[string]*healthCheckServiceResponse),
	}

	resp.Version.Tag = h.tag
	resp.Version.Commit = h.commit

	resp.System.Version = runtime.Version()
	resp.System.NumCPU = runtime.NumCPU()
	resp.System.NumGoroutines = runtime.NumGoroutine()

	mem := &runtime.MemStats{}
	runtime.ReadMemStats(mem)
	resp.System.AllocBytes = mem.HeapAlloc
	resp.System.TotalAllocBytes = mem.TotalAlloc
	resp.System.NumHeapObjects = mem.HeapObjects

	return resp
}

func (h *healthCheck) handler(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	resp := h.newResponse()
	h.serviceChecks(r, resp)

	resp.Lock()
	resp.Elapsed = time.Since(started) / time.Millisecond
	resp.Unlock()

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *healthCheck) serviceChecks(r *http.Request, resp *healthCheckResponse) {
	ctx := r.Context()
	var statusCode int32 = http.StatusOK

	h.servicesGuard.RLock()
	services := make(map[string]HealthChecker, len(h.services))
	for k, v := range h.services {
		services[k] = v
	}
	h.servicesGuard.RUnlock()
	var wg sync.WaitGroup
	for name, svc := range services {
		svcCheck := &healthCheckServiceResponse{
			Status: true,
		}

		resp.Checks[name] = svcCheck

		wg.Add(1)
		go func(svc HealthChecker, check *healthCheckServiceResponse) {
			defer wg.Done()
			started := time.Now()

			timeoutCtx, cancel := context.WithTimeout(ctx, h.serviceTimeout)
			go func() {
				defer cancel()

				detail, err := svc.HealthCheck(timeoutCtx)

				if timeoutCtx.Err() != nil {
					return
				}

				if err != nil {
					atomic.CompareAndSwapInt32(&statusCode, http.StatusOK, http.StatusServiceUnavailable)
					resp.Lock()
					resp.Status = false
					resp.Unlock()

					check.Lock()
					check.Status = false
					check.Error = err.Error()
					check.Unlock()
				}
				check.Lock()
				check.Detail = detail
				check.Unlock()
			}()

			<-timeoutCtx.Done()

			err := timeoutCtx.Err()
			if err != nil && err == context.DeadlineExceeded {
				atomic.CompareAndSwapInt32(&statusCode, http.StatusOK, http.StatusRequestTimeout)
				resp.Lock()
				resp.Status = false
				resp.Unlock()

				check.Lock()
				check.Status = false
				check.Error = err.Error()
				check.Unlock()
			}

			check.Lock()
			check.Elapsed = time.Since(started) / time.Millisecond
			check.Unlock()
		}(svc, svcCheck)
	}

	wg.Wait()
}

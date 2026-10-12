package policy

import (
	"errors"
	"reflect"
)

// Limits uses seconds for time values and bytes for storage values. All fields
// are mandatory. Defaults are operator conveniences, never parser fallbacks.
type Limits struct {
	RunSeconds            int64 `json:"run_seconds"`
	ConcurrentOperations  int64 `json:"concurrent_operations"`
	TotalOperations       int64 `json:"total_operations"`
	RequestBytes          int64 `json:"request_bytes"`
	HeaderBytes           int64 `json:"header_bytes"`
	HeaderCount           int64 `json:"header_count"`
	ModelResponseBytes    int64 `json:"model_response_bytes"`
	FetchResponseBytes    int64 `json:"fetch_response_bytes"`
	TotalRequestBytes     int64 `json:"total_request_bytes"`
	TotalResponseBytes    int64 `json:"total_response_bytes"`
	ReadHeaderSeconds     int64 `json:"read_header_seconds"`
	ReadBodySeconds       int64 `json:"read_body_seconds"`
	DNSSeconds            int64 `json:"dns_seconds"`
	ConnectSeconds        int64 `json:"connect_seconds"`
	TLSSeconds            int64 `json:"tls_seconds"`
	ResponseHeaderSeconds int64 `json:"response_header_seconds"`
	ModelSeconds          int64 `json:"model_seconds"`
	FetchSeconds          int64 `json:"fetch_seconds"`
	StreamIdleSeconds     int64 `json:"stream_idle_seconds"`
	WriteSeconds          int64 `json:"write_seconds"`
	CopyBufferBytes       int64 `json:"copy_buffer_bytes"`
	AuditRecordBytes      int64 `json:"audit_record_bytes"`
	AuditFileBytes        int64 `json:"audit_file_bytes"`
	SandboxMemoryBytes    int64 `json:"sandbox_memory_bytes"`
	SandboxProcesses      int64 `json:"sandbox_processes"`
	SandboxCPUCores       int64 `json:"sandbox_cpu_cores"`
	SandboxFDs            int64 `json:"sandbox_fds"`
	WorkspaceBytes        int64 `json:"workspace_bytes"`
	TempBytes             int64 `json:"temp_bytes"`
	LocalConnections      int64 `json:"local_connections"`
	RequestBufferBytes    int64 `json:"request_buffer_bytes"`
}

func DefaultLimits() Limits {
	return Limits{RunSeconds: 1800, ConcurrentOperations: 4, TotalOperations: 500, RequestBytes: 2 << 20, HeaderBytes: 16 << 10, HeaderCount: 64, ModelResponseBytes: 32 << 20, FetchResponseBytes: 2 << 20, TotalRequestBytes: 64 << 20, TotalResponseBytes: 128 << 20, ReadHeaderSeconds: 5, ReadBodySeconds: 10, DNSSeconds: 3, ConnectSeconds: 5, TLSSeconds: 5, ResponseHeaderSeconds: 30, ModelSeconds: 180, FetchSeconds: 30, StreamIdleSeconds: 30, WriteSeconds: 5, CopyBufferBytes: 32 << 10, AuditRecordBytes: 2 << 10, AuditFileBytes: 8 << 20, SandboxMemoryBytes: 1 << 30, SandboxProcesses: 128, SandboxCPUCores: 2, SandboxFDs: 256, WorkspaceBytes: 1 << 30, TempBytes: 256 << 20, LocalConnections: 8, RequestBufferBytes: 16 << 20}
}

func (l Limits) Validate() error {
	// The first release permits tightening the reviewed envelope, not raising it.
	value, max := reflect.ValueOf(l), reflect.ValueOf(DefaultLimits())
	for i := 0; i < value.NumField(); i++ {
		if value.Field(i).Int() < 1 || value.Field(i).Int() > max.Field(i).Int() {
			return errors.New("limit outside reviewed bounds")
		}
	}
	if l.ConcurrentOperations > l.TotalOperations || l.RequestBytes > l.TotalRequestBytes || l.RequestBytes > l.RequestBufferBytes || l.ModelResponseBytes > l.TotalResponseBytes || l.FetchResponseBytes > l.TotalResponseBytes || l.AuditRecordBytes > l.AuditFileBytes || l.ModelSeconds > l.RunSeconds || l.FetchSeconds > l.RunSeconds {
		return errors.New("inconsistent limits")
	}
	return nil
}

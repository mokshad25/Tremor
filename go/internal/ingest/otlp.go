package ingest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/mokshad/tremor/internal/event"
)

// unknownService is the OTel SDK default when service.name is not set.
const unknownService = "unknown_service"

// fromOTLP maps an OTLP export request onto TREMOR events:
//
//	resource attribute service.name -> Service (the shard key)
//	time_unix_nano (else observed_time_unix_nano, else receive time) -> Timestamp
//	severity_number (else severity_text) -> Level
//	body (AnyValue, rendered as text) -> Message
//	log attributes -> Attrs; other resource attributes -> Attrs["resource.<key>"]
//	trace_id / span_id -> Attrs["trace_id"] / ["span_id"] (hex)
//
// Oversized fields are clamped (event.Clamp) rather than rejected: an OTLP
// client cannot fix one bad record, and rejecting the batch would drop
// every good record with it.
func fromOTLP(req *collogspb.ExportLogsServiceRequest, received int64, maxEvents int) ([]event.Event, error) {
	n := 0
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			n += len(sl.GetLogRecords())
		}
	}
	if n > maxEvents {
		return nil, fmt.Errorf("%d log records in one request; limit %d (lower the collector's batch send_batch_max_size)", n, maxEvents)
	}
	events := make([]event.Event, 0, n)
	for _, rl := range req.GetResourceLogs() {
		service := unknownService
		var resAttrs []*commonpb.KeyValue
		for _, kv := range rl.GetResource().GetAttributes() {
			if kv.GetKey() == "service.name" {
				if s := anyString(kv.GetValue()); s != "" {
					service = s
				}
				continue
			}
			resAttrs = append(resAttrs, kv)
		}
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				ev := event.Event{
					Service:    service,
					ReceivedAt: received,
					Timestamp:  received,
					Level:      otlpLevel(lr.GetSeverityNumber(), lr.GetSeverityText()),
					Message:    anyString(lr.GetBody()),
				}
				if t := lr.GetTimeUnixNano(); t != 0 {
					ev.Timestamp = int64(t)
				} else if t := lr.GetObservedTimeUnixNano(); t != 0 {
					ev.Timestamp = int64(t)
				}
				if k := len(lr.GetAttributes()) + len(resAttrs); k > 0 || len(lr.GetTraceId()) > 0 {
					ev.Attrs = make(map[string]string, k+2)
					for _, kv := range lr.GetAttributes() {
						ev.Attrs[kv.GetKey()] = anyString(kv.GetValue())
					}
					for _, kv := range resAttrs {
						ev.Attrs["resource."+kv.GetKey()] = anyString(kv.GetValue())
					}
					if id := lr.GetTraceId(); len(id) > 0 {
						ev.Attrs["trace_id"] = hex.EncodeToString(id)
					}
					if id := lr.GetSpanId(); len(id) > 0 {
						ev.Attrs["span_id"] = hex.EncodeToString(id)
					}
				}
				event.Clamp(&ev)
				events = append(events, ev)
			}
		}
	}
	return events, nil
}

// otlpLevel maps OTLP severity numbers (1-4 TRACE, 5-8 DEBUG, 9-12 INFO,
// 13-16 WARN, 17-20 ERROR, 21-24 FATAL) onto TREMOR's four levels.
func otlpLevel(num logspb.SeverityNumber, text string) event.Level {
	switch n := int32(num); {
	case n <= 0:
		return event.ParseLevel(text)
	case n <= 8:
		return event.LevelDebug
	case n <= 12:
		return event.LevelInfo
	case n <= 16:
		return event.LevelWarning
	default:
		return event.LevelError
	}
}

// anyString renders an AnyValue as text: strings as-is, scalars in their
// usual text form, bytes as base64, arrays and maps as compact JSON.
func anyString(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(x.BoolValue)
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'g', -1, 64)
	case *commonpb.AnyValue_BytesValue:
		return base64.StdEncoding.EncodeToString(x.BytesValue)
	case *commonpb.AnyValue_ArrayValue, *commonpb.AnyValue_KvlistValue:
		b, _ := json.Marshal(anyJSON(v))
		return string(b)
	}
	return ""
}

func anyJSON(v *commonpb.AnyValue) any {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_ArrayValue:
		out := make([]any, 0, len(x.ArrayValue.GetValues()))
		for _, e := range x.ArrayValue.GetValues() {
			out = append(out, anyJSON(e))
		}
		return out
	case *commonpb.AnyValue_KvlistValue:
		out := make(map[string]any, len(x.KvlistValue.GetValues()))
		for _, kv := range x.KvlistValue.GetValues() {
			out[kv.GetKey()] = anyJSON(kv.GetValue())
		}
		return out
	case *commonpb.AnyValue_BoolValue:
		return x.BoolValue
	case *commonpb.AnyValue_IntValue:
		return x.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return x.DoubleValue
	}
	return anyString(v)
}

// ── OTLP/JSON ─────────────────────────────────────────────────────────
//
// OTLP/JSON is proto3 JSON with two deviations that protojson does not
// handle: trace_id/span_id are hex (not base64) and enum values may be
// numbers. This decoder covers the logs schema and builds the same proto
// request as the binary path, so both share fromOTLP.

type jsonExport struct {
	ResourceLogs []struct {
		Resource struct {
			Attributes []jsonKV `json:"attributes"`
		} `json:"resource"`
		ScopeLogs []struct {
			Scope struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"scope"`
			LogRecords []jsonLogRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

type jsonLogRecord struct {
	TimeUnixNano         jsonUint     `json:"timeUnixNano"`
	ObservedTimeUnixNano jsonUint     `json:"observedTimeUnixNano"`
	SeverityNumber       jsonSeverity `json:"severityNumber"`
	SeverityText         string       `json:"severityText"`
	Body                 *jsonAny     `json:"body"`
	Attributes           []jsonKV     `json:"attributes"`
	TraceID              string       `json:"traceId"`
	SpanID               string       `json:"spanId"`
}

type jsonKV struct {
	Key   string  `json:"key"`
	Value jsonAny `json:"value"`
}

type jsonAny struct {
	StringValue *string  `json:"stringValue"`
	BoolValue   *bool    `json:"boolValue"`
	IntValue    *jsonInt `json:"intValue"`
	DoubleValue *float64 `json:"doubleValue"`
	BytesValue  *string  `json:"bytesValue"` // base64
	ArrayValue  *struct {
		Values []jsonAny `json:"values"`
	} `json:"arrayValue"`
	KvlistValue *struct {
		Values []jsonKV `json:"values"`
	} `json:"kvlistValue"`
}

// jsonUint accepts 64-bit integers as JSON strings (proto3 JSON) or numbers.
type jsonUint uint64

func (u *jsonUint) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	*u = jsonUint(v)
	return err
}

type jsonInt int64

func (i *jsonInt) UnmarshalJSON(b []byte) error {
	v, err := strconv.ParseInt(strings.Trim(string(b), `"`), 10, 64)
	*i = jsonInt(v)
	return err
}

// jsonSeverity accepts a number or an enum name like "SEVERITY_NUMBER_WARN".
type jsonSeverity int32

func (s *jsonSeverity) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	if v, err := strconv.ParseInt(str, 10, 32); err == nil {
		*s = jsonSeverity(v)
		return nil
	}
	v, ok := logspb.SeverityNumber_value[str]
	if !ok {
		return fmt.Errorf("unknown severityNumber %q", str)
	}
	*s = jsonSeverity(v)
	return nil
}

func (a *jsonAny) proto() (*commonpb.AnyValue, error) {
	switch {
	case a == nil:
		return nil, nil
	case a.StringValue != nil:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: *a.StringValue}}, nil
	case a.BoolValue != nil:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: *a.BoolValue}}, nil
	case a.IntValue != nil:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(*a.IntValue)}}, nil
	case a.DoubleValue != nil:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: *a.DoubleValue}}, nil
	case a.BytesValue != nil:
		b, err := base64.StdEncoding.DecodeString(*a.BytesValue)
		if err != nil {
			return nil, fmt.Errorf("bytesValue: %w", err)
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BytesValue{BytesValue: b}}, nil
	case a.ArrayValue != nil:
		arr := &commonpb.ArrayValue{}
		for i := range a.ArrayValue.Values {
			v, err := a.ArrayValue.Values[i].proto()
			if err != nil {
				return nil, err
			}
			arr.Values = append(arr.Values, v)
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: arr}}, nil
	case a.KvlistValue != nil:
		kvs, err := kvsProto(a.KvlistValue.Values)
		if err != nil {
			return nil, err
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: kvs}}}, nil
	}
	return &commonpb.AnyValue{}, nil
}

func kvsProto(kvs []jsonKV) ([]*commonpb.KeyValue, error) {
	out := make([]*commonpb.KeyValue, 0, len(kvs))
	for i := range kvs {
		v, err := kvs[i].Value.proto()
		if err != nil {
			return nil, fmt.Errorf("attribute %q: %w", kvs[i].Key, err)
		}
		out = append(out, &commonpb.KeyValue{Key: kvs[i].Key, Value: v})
	}
	return out, nil
}

// decodeOTLPJSON parses an OTLP/JSON logs export request.
func decodeOTLPJSON(body []byte) (*collogspb.ExportLogsServiceRequest, error) {
	var in jsonExport
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, err
	}
	req := &collogspb.ExportLogsServiceRequest{}
	for _, rl := range in.ResourceLogs {
		attrs, err := kvsProto(rl.Resource.Attributes)
		if err != nil {
			return nil, err
		}
		prl := &logspb.ResourceLogs{Resource: &resourcepb.Resource{Attributes: attrs}}
		for _, sl := range rl.ScopeLogs {
			psl := &logspb.ScopeLogs{Scope: &commonpb.InstrumentationScope{Name: sl.Scope.Name, Version: sl.Scope.Version}}
			for i := range sl.LogRecords {
				lr := &sl.LogRecords[i]
				body, err := lr.Body.proto()
				if err != nil {
					return nil, err
				}
				la, err := kvsProto(lr.Attributes)
				if err != nil {
					return nil, err
				}
				p := &logspb.LogRecord{
					TimeUnixNano: uint64(lr.TimeUnixNano), ObservedTimeUnixNano: uint64(lr.ObservedTimeUnixNano),
					SeverityNumber: logspb.SeverityNumber(lr.SeverityNumber), SeverityText: lr.SeverityText,
					Body: body, Attributes: la,
				}
				if lr.TraceID != "" {
					if p.TraceId, err = hex.DecodeString(lr.TraceID); err != nil {
						return nil, fmt.Errorf("traceId: %w", err)
					}
				}
				if lr.SpanID != "" {
					if p.SpanId, err = hex.DecodeString(lr.SpanID); err != nil {
						return nil, fmt.Errorf("spanId: %w", err)
					}
				}
				psl.LogRecords = append(psl.LogRecords, p)
			}
			prl.ScopeLogs = append(prl.ScopeLogs, psl)
		}
		req.ResourceLogs = append(req.ResourceLogs, prl)
	}
	return req, nil
}

package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcgzip "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/mokshad/tremor/internal/event"
	"github.com/mokshad/tremor/internal/metrics"
	"github.com/mokshad/tremor/internal/pipeline"
	"github.com/mokshad/tremor/internal/redact"
)

func str(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}

func kv(k string, v *commonpb.AnyValue) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: v}
}

func sampleRequest() *collogspb.ExportLogsServiceRequest {
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			kv("service.name", str("checkout")), kv("host.name", str("node-7")),
		}},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{
			{
				TimeUnixNano: 1_767_621_600_000_000_000, SeverityNumber: logspb.SeverityNumber_SEVERITY_NUMBER_ERROR,
				Body:       str("Payment failed for priya@example.com card 4111111111111111"),
				Attributes: []*commonpb.KeyValue{kv("http.status_code", &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 502}}), kv("enduser.id", str("priya"))},
				TraceId:    bytes.Repeat([]byte{0xab}, 16), SpanId: bytes.Repeat([]byte{0xcd}, 8),
			},
			{ObservedTimeUnixNano: 1_767_621_601_000_000_000, SeverityText: "warn", Body: str("retrying")},
			{SeverityNumber: logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG2, Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: []*commonpb.KeyValue{kv("a", str("b"))}}}}},
		}}},
	}}}
}

func TestFromOTLPMapping(t *testing.T) {
	evs, err := fromOTLP(sampleRequest(), 42, 100)
	if err != nil || len(evs) != 3 {
		t.Fatalf("%v %d", err, len(evs))
	}
	e := evs[0]
	if e.Service != "checkout" || e.Level != event.LevelError || e.Timestamp != 1_767_621_600_000_000_000 || e.ReceivedAt != 42 {
		t.Fatalf("event 0: %+v", e)
	}
	want := map[string]string{"http.status_code": "502", "enduser.id": "priya", "resource.host.name": "node-7",
		"trace_id": strings.Repeat("ab", 16), "span_id": strings.Repeat("cd", 8)}
	for k, v := range want {
		if e.Attrs[k] != v {
			t.Errorf("attr %s = %q want %q", k, e.Attrs[k], v)
		}
	}
	if _, ok := e.Attrs["resource.service.name"]; ok {
		t.Error("service.name should become the service, not an attribute")
	}
	if evs[1].Level != event.LevelWarning || evs[1].Timestamp != 1_767_621_601_000_000_000 {
		t.Errorf("event 1 severity text / observed time: %+v", evs[1])
	}
	if evs[2].Level != event.LevelDebug || evs[2].Message != `{"a":"b"}` || evs[2].Timestamp != 42 {
		t.Errorf("event 2: %+v", evs[2])
	}
	noSvc := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{Body: str("x")}}}}}}}
	if evs, _ := fromOTLP(noSvc, 0, 10); evs[0].Service != unknownService {
		t.Errorf("missing service.name -> %q", evs[0].Service)
	}
	if _, err := fromOTLP(sampleRequest(), 0, 2); err == nil {
		t.Error("record limit not enforced")
	}
}

func TestDecodeOTLPJSON(t *testing.T) {
	body := `{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}}]},
	 "scopeLogs":[{"scope":{"name":"s"},"logRecords":[
	  {"timeUnixNano":"1767621600000000000","severityNumber":"SEVERITY_NUMBER_WARN","body":{"stringValue":"slow"},
	   "attributes":[{"key":"n","value":{"intValue":"7"}},{"key":"ok","value":{"boolValue":true}},{"key":"d","value":{"doubleValue":1.5}}],
	   "traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174"},
	  {"timeUnixNano":1767621600000000001,"severityNumber":17,"body":{"arrayValue":{"values":[{"stringValue":"x"},{"intValue":2}]}}}
	 ]}]}]}`
	req, err := decodeOTLPJSON([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	evs, err := fromOTLP(req, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if evs[0].Service != "api" || evs[0].Level != event.LevelWarning || evs[0].Timestamp != 1767621600000000000 ||
		evs[0].Attrs["n"] != "7" || evs[0].Attrs["ok"] != "true" || evs[0].Attrs["d"] != "1.5" ||
		evs[0].Attrs["trace_id"] != "5b8efff798038103d269b633813fc60c" {
		t.Fatalf("event 0: %+v", evs[0])
	}
	if evs[1].Level != event.LevelError || evs[1].Message != `["x",2]` || evs[1].Timestamp != 1767621600000000001 {
		t.Fatalf("event 1: %+v", evs[1])
	}
	for _, bad := range []string{`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"traceId":"zz"}]}]}]}`, `{"resourceLogs":`, `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"severityNumber":"NOPE"}]}]}]}`} {
		if _, err := decodeOTLPJSON([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

type otlpFixture struct {
	g    *Gateway
	q    *pipeline.Queue
	got  chan []event.Event
	wait func()
}

// newOTLPFixture runs a fake WAL stage that acks every batch and reports
// the events it received (after redaction).
func newOTLPFixture(t *testing.T, capacity int, consume bool) *otlpFixture {
	q := pipeline.NewQueue(capacity)
	red := redact.New([]byte("otlp-test-key-0123456789abcdef!!"))
	g := NewGateway(q, &metrics.Gateway{}, testOpts, red, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f := &otlpFixture{g: g, q: q, got: make(chan []event.Event, 16)}
	if consume {
		f.wait = pipeline.Run(q, 1, func(b *pipeline.Batch) error {
			b.FirstSeq, b.LastSeq = 1, uint64(len(b.Events))
			f.got <- b.Events
			return nil
		})
		t.Cleanup(func() { q.Close(); f.wait() })
	}
	return f
}

func assertRedacted(t *testing.T, evs []event.Event) {
	t.Helper()
	m := evs[0].Message
	if strings.Contains(m, "priya@example.com") || strings.Contains(m, "4111111111111111") || !strings.Contains(m, "<EMAIL>") || !strings.Contains(m, "<CARD>") {
		t.Fatalf("message reached the WAL queue unredacted: %q", m)
	}
	if !strings.HasPrefix(evs[0].Attrs["enduser.id"], "usr_") {
		t.Fatalf("username attribute not tokenized: %q", evs[0].Attrs["enduser.id"])
	}
}

func postOTLP(h http.Handler, ct string, body []byte, gz bool) *httptest.ResponseRecorder {
	if gz {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write(body)
		w.Close()
		body = buf.Bytes()
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestOTLPHTTPProtobufJSONAndGzip(t *testing.T) {
	f := newOTLPFixture(t, 4, true)
	h := f.g.OTLPHTTP()
	pb, _ := proto.Marshal(sampleRequest())
	for _, gz := range []bool{false, true} {
		rec := postOTLP(h, ctProtobuf, pb, gz)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != ctProtobuf || rec.Header().Get("X-Tremor-Seq") != "1-3" {
			t.Fatalf("protobuf gz=%v: %d %v", gz, rec.Code, rec.Header())
		}
		var resp collogspb.ExportLogsServiceResponse
		if err := proto.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		assertRedacted(t, <-f.got)
	}
	js := `{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}}]},"scopeLogs":[{"logRecords":[{"body":{"stringValue":"Payment failed for priya@example.com card 4111111111111111"},"attributes":[{"key":"enduser.id","value":{"stringValue":"priya"}}]}]}]}]}`
	rec := postOTLP(h, ctJSON, []byte(js), true)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != ctJSON || strings.TrimSpace(rec.Body.String()) != "{}" {
		t.Fatalf("json: %d %q", rec.Code, rec.Body)
	}
	assertRedacted(t, <-f.got)
}

func TestOTLPHTTPErrors(t *testing.T) {
	f := newOTLPFixture(t, 1, false)
	h := f.g.OTLPHTTP()
	if rec := postOTLP(h, "text/plain", []byte("x"), false); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type: %d", rec.Code)
	}
	rec := postOTLP(h, ctProtobuf, []byte{0xff, 0xff, 0xff}, false)
	var st statuspb.Status
	if rec.Code != http.StatusBadRequest || proto.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Code != int32(codes.InvalidArgument) {
		t.Fatalf("malformed: %d %v", rec.Code, &st)
	}
	if f.q.InFlight() != 0 {
		t.Fatal("slot leaked on a bad request")
	}
	// Queue full: 429 + Retry-After + Status body, retryable by OTLP exporters.
	f.q.Acquire()
	pb, _ := proto.Marshal(sampleRequest())
	rec = postOTLP(h, ctProtobuf, pb, false)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("overload: %d %v", rec.Code, rec.Header())
	}
	f.q.Release()
	// Gzip bomb: decompressed size is limited too.
	big, _ := proto.Marshal(&collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{Body: str(strings.Repeat("a", 64<<10))}}}}}}})
	if rec := postOTLP(h, ctProtobuf, big, true); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("decompressed limit: %d", rec.Code)
	}
	// Empty export is a success with nothing stored.
	empty, _ := proto.Marshal(&collogspb.ExportLogsServiceRequest{})
	if rec := postOTLP(h, ctProtobuf, empty, false); rec.Code != http.StatusOK || f.q.InFlight() != 0 {
		t.Fatalf("empty: %d inflight %d", rec.Code, f.q.InFlight())
	}
}

func startGRPC(t *testing.T, f *otlpFixture) collogspb.LogsServiceClient {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := f.g.NewOTLPGRPCServer()
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(grpcgzip.Name)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return collogspb.NewLogsServiceClient(conn)
}

func TestOTLPGRPC(t *testing.T) {
	f := newOTLPFixture(t, 1, true)
	client := startGRPC(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Export(ctx, sampleRequest()); err != nil {
		t.Fatal(err)
	}
	assertRedacted(t, <-f.got)
}

func TestOTLPGRPCOverloadAndInvalid(t *testing.T) {
	f := newOTLPFixture(t, 1, false)
	client := startGRPC(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.q.Acquire() // queue full
	_, err := client.Export(ctx, sampleRequest())
	st := status.Convert(err)
	if st.Code() != codes.ResourceExhausted {
		t.Fatalf("overload code %v", st.Code())
	}
	var retry *errdetails.RetryInfo
	for _, d := range st.Details() {
		if ri, ok := d.(*errdetails.RetryInfo); ok {
			retry = ri
		}
	}
	if retry == nil || retry.RetryDelay.AsDuration() != 2*time.Second {
		t.Fatalf("missing RetryInfo: %v", st.Details())
	}
	f.q.Release()
	tooMany := sampleRequest()
	for range testOpts.MaxEventsPerBatch {
		tooMany.ResourceLogs[0].ScopeLogs[0].LogRecords = append(tooMany.ResourceLogs[0].ScopeLogs[0].LogRecords, &logspb.LogRecord{Body: str("x")})
	}
	if _, err := client.Export(ctx, tooMany); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("too many records: %v", err)
	}
	if f.q.InFlight() != 0 {
		t.Fatal("slot leaked")
	}
}

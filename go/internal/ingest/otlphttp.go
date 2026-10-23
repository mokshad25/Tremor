package ingest

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	ctProtobuf = "application/x-protobuf"
	ctJSON     = "application/json"
)

// OTLPHTTP returns the OTLP/HTTP handler (POST /v1/logs), per the OTLP
// spec: protobuf or JSON bodies, optional gzip, the response in the
// request's encoding, 429/503 with Retry-After on overload (retryable by
// every OTLP exporter), and 400 for malformed data (not retryable).
func (g *Gateway) OTLPHTTP() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/logs", g.otlpLogs)
	return mux
}

func (g *Gateway) otlpLogs(w http.ResponseWriter, r *http.Request) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != ctProtobuf && ct != ctJSON {
		g.m.Requests.Add(1)
		g.m.RejectedBad.Add(1)
		http.Error(w, "unsupported content type: use application/x-protobuf or application/json", http.StatusUnsupportedMediaType)
		return
	}
	if rej := g.admit(); rej != nil {
		w.Header().Set("Retry-After", g.retryAfter)
		status := http.StatusServiceUnavailable
		if rej.Overload {
			status = http.StatusTooManyRequests
		}
		writeOTLPStatus(w, ct, status, codes.Unavailable, rej.Reason)
		return
	}
	body, err := g.readOTLPBody(w, r)
	if err != nil {
		g.release()
		var tooBig *http.MaxBytesError
		status := http.StatusBadRequest
		if errors.As(err, &tooBig) || errors.Is(err, errDecompressedTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeOTLPStatus(w, ct, status, codes.InvalidArgument, err.Error())
		return
	}
	var req *collogspb.ExportLogsServiceRequest
	if ct == ctProtobuf {
		req = &collogspb.ExportLogsServiceRequest{}
		err = proto.Unmarshal(body, req)
	} else {
		req, err = decodeOTLPJSON(body)
	}
	if err != nil {
		g.release()
		writeOTLPStatus(w, ct, http.StatusBadRequest, codes.InvalidArgument, "decode: "+err.Error())
		return
	}
	events, err := fromOTLP(req, g.now().UnixNano(), g.opt.MaxEventsPerBatch)
	if err != nil {
		g.release()
		writeOTLPStatus(w, ct, http.StatusBadRequest, codes.InvalidArgument, err.Error())
		return
	}
	if len(events) == 0 {
		g.q.Release() // valid but empty: success, nothing to store
		g.m.RequestsAccepted.Add(1)
		writeOTLPResponse(w, ct)
		return
	}
	batch, err := g.commit(r.Context(), events, len(body))
	if err != nil {
		var rej *Rejection
		if errors.As(err, &rej) {
			w.Header().Set("Retry-After", g.retryAfter)
			status := http.StatusServiceUnavailable
			if rej.Overload {
				status = http.StatusTooManyRequests
			}
			writeOTLPStatus(w, ct, status, codes.Unavailable, rej.Reason)
		}
		return
	}
	w.Header().Set("X-Tremor-Seq", fmt.Sprintf("%d-%d", batch.FirstSeq, batch.LastSeq))
	writeOTLPResponse(w, ct)
}

var errDecompressedTooLarge = errors.New("decompressed body too large")

// readOTLPBody reads the body, gunzipping if needed. The size limit applies
// to the decompressed bytes too, so a small gzip bomb cannot exhaust memory.
func (g *Gateway) readOTLPBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	var src io.Reader = http.MaxBytesReader(w, r.Body, g.opt.MaxBodyBytes)
	switch enc := r.Header.Get("Content-Encoding"); enc {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(src)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		src = io.LimitReader(gz, g.opt.MaxBodyBytes+1)
	default:
		return nil, fmt.Errorf("unsupported Content-Encoding %q", enc)
	}
	b, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > g.opt.MaxBodyBytes {
		return nil, errDecompressedTooLarge
	}
	return b, nil
}

func writeOTLPResponse(w http.ResponseWriter, ct string) {
	resp := &collogspb.ExportLogsServiceResponse{}
	var b []byte
	if ct == ctJSON {
		b, _ = protojson.Marshal(resp)
	} else {
		b, _ = proto.Marshal(resp)
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// writeOTLPStatus writes a google.rpc.Status body, as the OTLP/HTTP spec
// requires for failures.
func writeOTLPStatus(w http.ResponseWriter, ct string, httpStatus int, code codes.Code, msg string) {
	st := &statuspb.Status{Code: int32(code), Message: msg}
	var b []byte
	if ct == ctJSON {
		b, _ = protojson.Marshal(st)
	} else {
		b, _ = proto.Marshal(st)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(httpStatus)
	_, _ = w.Write(b)
}

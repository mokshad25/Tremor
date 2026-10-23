package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	_ "google.golang.org/grpc/encoding/gzip" // the Collector's OTLP exporter gzips by default
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// otlpGRPC implements the OTLP LogsService.
type otlpGRPC struct {
	collogspb.UnimplementedLogsServiceServer
	g *Gateway
}

// NewOTLPGRPCServer returns a gRPC server exposing LogsService/Export.
// Message size is capped at the gateway's body limit and concurrent streams
// at the admission capacity, so gRPC cannot buffer more than HTTP would.
func (g *Gateway) NewOTLPGRPCServer() *grpc.Server {
	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(int(g.opt.MaxBodyBytes)),
		grpc.MaxConcurrentStreams(uint32(max(g.q.Capacity(), 1))),
	)
	collogspb.RegisterLogsServiceServer(srv, &otlpGRPC{g: g})
	return srv
}

// Export follows the OTLP/gRPC spec: overload is RESOURCE_EXHAUSTED and
// draining is UNAVAILABLE, both with a RetryInfo delay, which OTLP
// exporters treat as retryable with backoff; malformed data is
// INVALID_ARGUMENT, which they do not retry.
func (s *otlpGRPC) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	g := s.g
	if rej := g.admit(); rej != nil {
		return nil, s.retryable(rej)
	}
	events, err := fromOTLP(req, g.now().UnixNano(), g.opt.MaxEventsPerBatch)
	if err != nil {
		g.release()
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if len(events) == 0 {
		g.q.Release()
		g.m.RequestsAccepted.Add(1)
		return &collogspb.ExportLogsServiceResponse{}, nil
	}
	batch, err := g.commit(ctx, events, proto.Size(req))
	if err != nil {
		var rej *Rejection
		if errors.As(err, &rej) {
			return nil, s.retryable(rej)
		}
		return nil, status.FromContextError(err).Err()
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-tremor-seq", fmt.Sprintf("%d-%d", batch.FirstSeq, batch.LastSeq)))
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func (s *otlpGRPC) retryable(rej *Rejection) error {
	code := codes.Unavailable
	if rej.Overload {
		code = codes.ResourceExhausted
	}
	st, err := status.New(code, rej.Reason).WithDetails(&errdetails.RetryInfo{
		RetryDelay: durationpb.New(time.Duration(s.g.retryAfterSecs) * time.Second),
	})
	if err != nil {
		return status.Error(code, rej.Reason)
	}
	return st.Err()
}

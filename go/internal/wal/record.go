// Package wal is TREMOR's write-ahead log: append-only segment files of
// checksummed, sequence-numbered records, group-committed with fsync, plus
// per-shard checkpoints that say how far processing has got.
//
// Record layout (little endian):
//
//	length  u32  = 8 + len(payload)      (covers seq + payload)
//	crc     u32  = CRC-32C(seq || payload)
//	seq     u64
//	payload []byte                       (event.AppendBinary)
//
// The length comes first so a reader can skip without decoding. The checksum
// covers the sequence number too, so a torn write cannot produce a valid
// record with a stale seq.
package wal

import (
	"bufio"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
)

const (
	recordHeaderSize = 8 // length + crc
	seqSize          = 8
	// maxRecordLen bounds a record's length field. Events are capped well
	// below this (event.MaxMessageLen, MaxAttrs...), so anything larger is
	// garbage from a torn write, not a real record.
	maxRecordLen = 1 << 20
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// errTorn means the bytes at this position are not a complete, valid record:
// a partial write, garbage, or a checksum mismatch.
var errTorn = errors.New("wal: torn or corrupt record")

// appendRecord appends a framed record whose payload is produced by fill.
func appendRecord(buf []byte, seq uint64, fill func([]byte) []byte) []byte {
	start := len(buf)
	buf = append(buf, make([]byte, recordHeaderSize)...)
	buf = binary.LittleEndian.AppendUint64(buf, seq)
	buf = fill(buf)
	body := buf[start+recordHeaderSize:]
	binary.LittleEndian.PutUint32(buf[start:], uint32(len(body)))
	binary.LittleEndian.PutUint32(buf[start+4:], crc32.Checksum(body, castagnoli))
	return buf
}

// readRecord reads one record from r into scratch (grown as needed). It
// returns io.EOF only at a clean record boundary; any partial or invalid
// record yields errTorn. n is the number of bytes the record occupied.
func readRecord(r *bufio.Reader, scratch []byte) (seq uint64, payload []byte, n int, buf []byte, err error) {
	var hdr [recordHeaderSize]byte
	if k, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF && k == 0 {
			return 0, nil, 0, scratch, io.EOF
		}
		return 0, nil, 0, scratch, errTorn
	}
	length := binary.LittleEndian.Uint32(hdr[0:])
	sum := binary.LittleEndian.Uint32(hdr[4:])
	if length < seqSize || length > maxRecordLen {
		return 0, nil, 0, scratch, errTorn
	}
	if cap(scratch) < int(length) {
		scratch = make([]byte, length)
	}
	body := scratch[:length]
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, 0, scratch, errTorn
	}
	if crc32.Checksum(body, castagnoli) != sum {
		return 0, nil, 0, scratch, errTorn
	}
	seq = binary.LittleEndian.Uint64(body)
	return seq, body[seqSize:], recordHeaderSize + int(length), scratch, nil
}

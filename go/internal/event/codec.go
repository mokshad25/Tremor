package event

import (
	"encoding/binary"
	"errors"
	"slices"
)

// Binary encoding used for WAL payloads. Seq is not included: the WAL record
// header carries it.
//
//	version   u8 (=1)
//	level     u8
//	timestamp varint
//	received  varint
//	service   uvarint len + bytes
//	message   uvarint len + bytes
//	nattrs    uvarint
//	attrs     nattrs x (key uvarint len + bytes, value uvarint len + bytes), sorted by key
//
// Attributes are written in key order so encoding is deterministic, which
// keeps tests and checksums reproducible.
const codecVersion = 1

var errCorrupt = errors.New("event: corrupt encoding")

// AppendBinary appends the encoding of e to buf.
func AppendBinary(buf []byte, e *Event) []byte {
	buf = append(buf, codecVersion, byte(e.Level))
	buf = binary.AppendVarint(buf, e.Timestamp)
	buf = binary.AppendVarint(buf, e.ReceivedAt)
	buf = appendString(buf, e.Service)
	buf = appendString(buf, e.Message)
	buf = binary.AppendUvarint(buf, uint64(len(e.Attrs)))
	if len(e.Attrs) > 0 {
		keys := make([]string, 0, len(e.Attrs))
		for k := range e.Attrs {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			buf = appendString(buf, k)
			buf = appendString(buf, e.Attrs[k])
		}
	}
	return buf
}

func appendString(buf []byte, s string) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(s)))
	return append(buf, s...)
}

// DecodeBinary decodes data (produced by AppendBinary) into e. e.Seq is left
// untouched. Strings are copied, so data may be reused afterwards.
func DecodeBinary(data []byte, e *Event) error {
	d := decoder{b: data}
	if d.byte() != codecVersion {
		return errors.New("event: unknown encoding version")
	}
	lvl := d.byte()
	if lvl > byte(LevelError) {
		return errCorrupt
	}
	e.Level = Level(lvl)
	e.Timestamp = d.varint()
	e.ReceivedAt = d.varint()
	e.Service = d.string()
	e.Message = d.string()
	n := d.uvarint()
	if n > MaxAttrs || d.err != nil {
		return errCorrupt
	}
	e.Attrs = nil
	if n > 0 {
		e.Attrs = make(map[string]string, n)
		for range n {
			k := d.string()
			e.Attrs[k] = d.string()
		}
	}
	if d.err != nil || len(d.b) != 0 {
		return errCorrupt
	}
	return nil
}

type decoder struct {
	b   []byte
	err error
}

func (d *decoder) byte() byte {
	if d.err != nil || len(d.b) < 1 {
		d.err = errCorrupt
		return 0
	}
	v := d.b[0]
	d.b = d.b[1:]
	return v
}

func (d *decoder) varint() int64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.err = errCorrupt
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) uvarint() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.err = errCorrupt
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) string() string {
	n := d.uvarint()
	if d.err != nil || n > uint64(len(d.b)) {
		d.err = errCorrupt
		return ""
	}
	s := string(d.b[:n])
	d.b = d.b[n:]
	return s
}

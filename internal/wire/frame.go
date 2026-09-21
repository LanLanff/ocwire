// Package wire 提供 oc-link 底层帧收发：4 字节大端长度前缀 + 载荷。
//
// 为什么用长度前缀而不是换行分隔：文件内容这类载荷可能很大，
// 长度前缀可以稳妥承载，且不需要转义。
package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// MaxFrame 单帧上限，防止对端发个超大长度把内存打爆（DoS 防护之一）。
const MaxFrame = 32 << 20 // 32MB

// WriteFrame 写入一帧。
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return errors.New("frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame 读取一帧。
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, errors.New("frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Linux TUN offload needs room before each packet for a virtio-net header.
// This matches WireGuard's packet headroom and also works when offload is off.
const tunOffset = 16

// maxIPPacketSize is the largest packet described by the IPv6 payload-length
// field (40-byte base header plus a 65535-byte payload).
const maxIPPacketSize = 40 + 0xffff

type StreamGetter func(netip.Addr) (io.Writer, bool)

func ClientForwardTunToStream(ctx context.Context, dev tun.Device, conn io.Writer) error {
	streamGetter := func(netip.Addr) (io.Writer, bool) {
		return conn, true
	}
	return forwardTunToStream(ctx, dev, streamGetter, false)
}

func ServerForwardTunToStream(ctx context.Context, dev tun.Device, streamGetter StreamGetter) error {
	return forwardTunToStream(ctx, dev, streamGetter, true)
}

func forwardTunToStream(ctx context.Context, dev tun.Device, streamGetter StreamGetter, ignoreIOErr bool) error {
	mtu, err := dev.MTU()
	if err != nil {
		return err
	}
	bufSize := mtu + tunOffset
	batchSize := dev.BatchSize()
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	buf := make([]byte, batchSize*bufSize)
	for i := range bufs {
		star, end := i*bufSize, (i+1)*bufSize
		bufs[i] = buf[star:end:end]
	}

	bufPool := NewPool(func() *bytes.Buffer {
		b := bytes.NewBuffer(make([]byte, mtu))
		b.Reset()
		return b
	})

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := dev.Read(bufs, sizes, tunOffset)
		if err != nil {
			return err
		}

		writeGroup := make(map[netip.Addr]*bytes.Buffer, n)
		for i, buf := range bufs[:n] {
			if sizes[i] == 0 {
				continue
			}
			packet := buf[tunOffset : tunOffset+sizes[i]]
			version := packet[0] >> 4
			switch version {
			case 4:
				if len(packet) < 20 {
					continue
				}
				_ = packet[19]
				addr := netip.AddrFrom4([4]byte(packet[16:]))
				buf, ok := writeGroup[addr]
				if !ok {
					buf = bufPool.Get()
				}
				buf.Write(packet)
				writeGroup[addr] = buf
			case 6:
				slog.Debug("ForwardTunToStream:unsupport ipv6")
			default:

			}

		}
		for addr, buf := range writeGroup {
			err := func() error {
				defer func() {
					buf.Reset()
					bufPool.Put(buf)
				}()
				conn, ok := streamGetter(addr)
				if !ok {
					return nil
				}
				return writeAll(conn, buf.Bytes())
			}()
			if err != nil {
				if ignoreIOErr {
					slog.Error("ForwardTunToStream:stream.Write", "error", err)
				} else {
					return fmt.Errorf("stream.Write:%w", err)
				}
			}
		}
	}
}

func ClientForwardStreamToTun(ctx context.Context, dev tun.Device, stream io.ReadCloser) error {
	return forwardStreamToTun(ctx, dev, stream, false)
}

func ServerForwardStreamToTun(ctx context.Context, dev tun.Device, stream io.ReadCloser) error {
	return forwardStreamToTun(ctx, dev, stream, true)
}

func forwardStreamToTun(ctx context.Context, dev tun.Device, stream io.ReadCloser, sharedDevice bool) error {
	mtu, err := dev.MTU()
	if err != nil {
		return err
	}
	bufSize := mtu + tunOffset
	batchSize := dev.BatchSize()
	batch := newBatchWrite(bufSize, batchSize)

	wg := sync.WaitGroup{}
	wg.Add(2)
	errCh := make(chan []error, 1)
	errCh <- nil
	go func() {
		defer wg.Done()
		if runErr := batch.run(dev); runErr != nil {
			errs := <-errCh
			errs = append(errs, fmt.Errorf("batch run:%w", runErr))
			errCh <- errs
			batch.close()
		}
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		defer batch.close()
		defer func() {
			if !sharedDevice {
				_ = dev.Close()
			}
		}()
		if readErr := readStream(batch, stream, mtu); readErr != nil {
			errs := <-errCh
			errs = append(errs, fmt.Errorf("stream read:%w", readErr))
			errCh <- errs
		}
	}()
	wg.Wait()
	return errors.Join(<-errCh...)
}

func readStream(batch *batchWrite, stream io.Reader, mtu int) error {
	readBufSize := cap(batch.bufQueue) * (mtu + tunOffset)
	if readBufSize < maxIPPacketSize {
		readBufSize = maxIPPacketSize
	}
	readBuf := make([]byte, readBufSize)
	pending := readBuf[:0]
	var readErr error
	buf := batch.swapBuf(nil)
	if buf == nil {
		return io.ErrClosedPipe
	}

	for {
		for len(pending) > 0 {
			n, ok, err := ipPacketSize(pending)
			if err != nil {
				return err
			}
			if !ok {
				break
			}

			// Drop packets that cannot be accepted by this TUN, but only after the
			// whole packet is available so the next packet remains aligned.
			if n <= mtu {
				copy(buf[tunOffset:tunOffset+n], pending[:n])
				buf = batch.swapBuf(buf[:tunOffset+n])
			}
			pending = pending[n:]
		}
		if readErr != nil {
			if len(pending) != 0 {
				return io.ErrUnexpectedEOF
			}
			return readErr
		}

		if len(pending) == cap(readBuf) {
			return fmt.Errorf("ip packet exceeds maximum supported size")
		}
		// Move an incomplete packet to the front before extending it with one
		// large Read. This avoids a ReadFull call and commonly handles several
		// packets in a single system call.
		copy(readBuf, pending)
		pending = readBuf[:len(pending)]
		n, err := stream.Read(readBuf[len(pending):])
		if n > 0 {
			pending = pending[:len(pending)+n]
		}
		if err != nil {
			if n > 0 {
				readErr = err
				continue
			}
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
}

// ipPacketSize returns a complete packet's size. ok is false when more stream
// data is needed to determine or complete the current packet.
func ipPacketSize(packet []byte) (n int, ok bool, err error) {
	if len(packet) < 1 {
		return 0, false, nil
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 4 {
			return 0, false, nil
		}
		ihl := int(packet[0]&0x0f) * 4
		n = int(binary.BigEndian.Uint16(packet[2:4]))
		if ihl < 20 || n < ihl {
			return 0, false, fmt.Errorf("invalid ipv4 packet size:%d", n)
		}
	case 6:
		if len(packet) < 6 {
			return 0, false, nil
		}
		n = 40 + int(binary.BigEndian.Uint16(packet[4:6]))
	default:
		return 0, false, fmt.Errorf("invalid ip version:%d", packet[0]>>4)
	}
	return n, len(packet) >= n, nil
}

func writeAll(w io.Writer, buf []byte) error {
	for len(buf) != 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

type batchWrite struct {
	fullCh     chan struct{}
	bufQueue   chan []byte
	readyQueue chan []byte
	done       chan struct{}
	doneOnce   sync.Once
}

func newBatchWrite(bufSize, batchSize int) *batchWrite {
	buf := make([]byte, batchSize*bufSize)
	b := batchWrite{
		fullCh:     make(chan struct{}, 1),
		bufQueue:   make(chan []byte, batchSize),
		readyQueue: make(chan []byte, batchSize),
		done:       make(chan struct{}),
	}
	for i := 0; i < batchSize; i++ {
		star, end := i*bufSize, (i+1)*bufSize
		b.bufQueue <- buf[star:end:end]
	}
	return &b
}

func (b *batchWrite) close() {
	b.doneOnce.Do(func() { close(b.done) })
}

func (b *batchWrite) swapBuf(in []byte) []byte {
	if in != nil {
		select {
		case b.readyQueue <- in:
		case <-b.done:
			return nil
		}
	}

	select {
	case buf := <-b.bufQueue:
		return buf
	case <-b.done:
		return nil
	default:
	}

	select {
	case b.fullCh <- struct{}{}:
	default:
	}
	select {
	case buf := <-b.bufQueue:
		return buf
	case <-b.done:
		return nil
	}
}

func (b *batchWrite) run(dev tun.Device) error {
	bufs := make([][]byte, 0, len(b.bufQueue))
	for {
		bufs = bufs[:0]
		select {
		case buf := <-b.readyQueue:
			bufs = append(bufs, buf)
		case <-b.done:
			// The reader closes done after queueing its final packet. Flush any
			// already queued packets before stopping the batch writer.
			select {
			case buf := <-b.readyQueue:
				bufs = append(bufs, buf)
			default:
				return nil
			}
		}
		t := time.NewTimer(time.Millisecond)
		for {
			select {
			case buf := <-b.readyQueue:
				bufs = append(bufs, buf)
			case <-b.fullCh:
				goto flush
			case <-t.C:
				goto flush
			case <-b.done:
				for {
					select {
					case buf := <-b.readyQueue:
						bufs = append(bufs, buf)
					default:
						goto flush
					}
				}
			}
		}
	flush:
		err := b.write(dev, bufs)
		if err != nil {
			return err
		}
	}

}

func (b *batchWrite) write(dev tun.Device, bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	_, err := dev.Write(bufs, tunOffset)
	if err != nil {
		return fmt.Errorf("batch write:%w", err)
	}
	for _, buf := range bufs {
		buf = buf[:cap(buf)]
		b.bufQueue <- buf
	}
	return nil
}

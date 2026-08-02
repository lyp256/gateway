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
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Linux TUN offload needs room before each packet for a virtio-net header.
// This matches WireGuard's packet headroom and also works when offload is off.
const tunOffset = 16

// maxIPPacketSize is the largest packet described by the IPv6 payload-length
// field (40-byte base header plus a 65535-byte payload).
const maxIPPacketSize = 40 + 0xffff

var errClosed = fmt.Errorf("batch writer closed")

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

func newReadBuffers(mtu int, batchSize int) [][]byte {
	bufSize := mtu + tunOffset
	bufs := make([][]byte, batchSize)
	buf := make([]byte, batchSize*bufSize)
	for i := range bufs {
		star, end := i*bufSize, (i+1)*bufSize
		bufs[i] = buf[star:end:end]
	}
	return bufs
}

func forwardTunToStream(ctx context.Context, dev tun.Device, streamGetter StreamGetter, ignoreIOErr bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	currentMTU, err := dev.MTU()
	if err != nil {
		return err
	}
	devMTU := uint32(currentMTU)
	batchSize := dev.BatchSize()
	sizes := make([]int, batchSize)
	bufs := newReadBuffers(currentMTU, batchSize)
	bufPool := NewPool(func() *bytes.Buffer {
		b := bytes.NewBuffer(make([]byte, currentMTU))
		b.Reset()
		return b
	})

	go func() {
		eventCh := dev.Events()
		for {
			select {
			case event := <-eventCh:
				if event == tun.EventMTUUpdate {
					newMtu, err := dev.MTU()
					if err != nil {
						slog.Error("get new MTU failed", "err", err)
					}
					atomic.StoreUint32(&devMTU, uint32(newMtu))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

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
		newMTU := int(atomic.LoadUint32(&devMTU))
		if newMTU != currentMTU {
			currentMTU = newMTU
			bufs = newReadBuffers(currentMTU, batchSize)
		}

	}
}

func ForwardStreamToTun(ctx context.Context, dev tun.Device, stream io.ReadCloser) error {
	mtu, err := dev.MTU()
	if err != nil {
		return err
	}
	batchSize := dev.BatchSize()
	batch := newBatchWrite(mtu+tunOffset, batchSize)
	var currentMTU atomic.Int64
	currentMTU.Store(int64(mtu))

	eventCtx, cancelEvents := context.WithCancel(ctx)
	defer cancelEvents()
	go func() {
		for {
			select {
			case <-eventCtx.Done():
				return
			case event, ok := <-dev.Events():
				if !ok {
					return
				}
				if event != tun.EventMTUUpdate {
					continue
				}
				newMTU, err := dev.MTU()
				if err != nil {
					slog.Error("ForwardStreamToTun: get new MTU failed", "err", err)
					continue
				}
				currentMTU.Store(int64(newMTU))
			}
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(2)
	errCh := make(chan []error, 1)
	errCh <- nil
	go func() {
		defer wg.Done()
		defer func() { _ = stream.Close() }()
		if runErr := batch.run(ctx, dev); runErr != nil {
			errs := <-errCh
			errs = append(errs, fmt.Errorf("batch run:%w", runErr))
			errCh <- errs
			batch.close()
		}
	}()
	go func() {
		defer wg.Done()
		defer batch.close()
		if readErr := readStreamWithMTU(batch, stream, func() int {
			return int(currentMTU.Load())
		}); readErr != nil {
			errs := <-errCh
			errs = append(errs, fmt.Errorf("stream read:%w", readErr))
			errCh <- errs
		}
	}()
	wg.Wait()
	return errors.Join(<-errCh...)
}

func readStream(batch *batchWrite, stream io.Reader, mtu int) error {
	return readStreamWithMTU(batch, stream, func() int { return mtu })
}

func readStreamWithMTU(batch *batchWrite, stream io.Reader, mtu func() int) error {
	readBufSize := cap(batch.bufQueue) * (mtu() + tunOffset)
	if readBufSize < maxIPPacketSize {
		readBufSize = maxIPPacketSize
	}
	readBuf := make([]byte, readBufSize)
	pending := readBuf[:0]
	var readErr error
	buf, _ := batch.swapBufSize(nil, tunOffset+mtu())
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
			if n <= mtu() {
				copy(buf[tunOffset:tunOffset+n], pending[:n])
				buf, ok = batch.swapBufSize(buf[:tunOffset+n], tunOffset+n)
				if !ok {
					return errClosed
				}
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

	closed uint32
}

func newBatchWrite(bufSize, batchSize int) *batchWrite {
	buf := make([]byte, batchSize*bufSize)
	b := batchWrite{
		fullCh:     make(chan struct{}, 1),
		bufQueue:   make(chan []byte, batchSize),
		readyQueue: make(chan []byte, batchSize),
	}
	for i := 0; i < batchSize; i++ {
		star, end := i*bufSize, (i+1)*bufSize
		b.bufQueue <- buf[star:end:end]
	}
	return &b
}

func (b *batchWrite) close() {
	close(b.bufQueue)
	close(b.readyQueue)

}

func (b *batchWrite) swapBuf(in []byte) ([]byte, bool) {
	if in != nil {
		if atomic.LoadUint32(&b.closed) != 0 {
			return nil, false
		}
		select {
		case b.readyQueue <- in:
		}
	}

	select {
	case buf, ok := <-b.bufQueue:
		return buf, ok
	default:
	}

	select {
	case b.fullCh <- struct{}{}:
	default:
	}
	select {
	case buf, ok := <-b.bufQueue:
		return buf, ok
	}
}

// swapBufSize is swapBuf with a minimum capacity requirement. It allows the
// batch to grow when the device MTU increases without replacing its queues.
func (b *batchWrite) swapBufSize(in []byte, size int) ([]byte, bool) {
	buf, ok := b.swapBuf(in)
	if !ok {
		return nil, false
	}
	if cap(buf) < size {
		buf = make([]byte, size)
	}
	return buf, true
}

func (b *batchWrite) run(ctx context.Context, dev tun.Device) error {

	bufs := make([][]byte, 0, len(b.bufQueue))
	for {
		bufs = bufs[:0]
		select {
		case buf := <-b.readyQueue:
			bufs = append(bufs, buf)
		case <-ctx.Done():
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
			case <-ctx.Done():
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
		for _, buf := range bufs {
			buf = buf[:cap(buf)]
			if atomic.LoadUint32(&b.closed) != 0 {
				return errClosed
			}
			b.bufQueue <- buf
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
	return nil
}

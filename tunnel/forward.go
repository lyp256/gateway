package tunnel

import (
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
				conn, ok := streamGetter(addr)
				if !ok {
					continue
				}
				err = writeAll(conn, packet)
				if err != nil {
					if ignoreIOErr {
						slog.Error("ForwardTunToStream:stream.Write", "error", err)
					} else {
						return fmt.Errorf("stream.Write:%w", err)
					}
				}
			case 6:
				slog.Debug("ForwardTunToStream:unsupport ipv6")
			default:

			}
		}
	}
}

func ForwardStreamToTun(ctx context.Context, dev tun.Device, stream io.ReadCloser) error {
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
	go func() {
		defer wg.Done()
		err = batch.run(dev, time.Millisecond)
		if err != nil {
			errs := <-errCh
			errs = append(errs, fmt.Errorf("batch run:%w", err))
			errCh <- errs
		}
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		defer func() {
			_ = dev.Close()
		}()
		buf := batch.swapBuf(nil)
		packet := buf[tunOffset:]
		for {
			_, err := io.ReadFull(stream, packet[:20])
			if err != nil {
				errs := <-errCh
				errs = append(errs, fmt.Errorf("stream.Read:%w", err))
				errCh <- errs
				return
			}

			var n int
			switch packet[0] >> 4 {
			case 4:
				ihl := int(packet[0]&0x0f) * 4
				n = int(binary.BigEndian.Uint16(packet[2:4]))
				if ihl < 20 || n < ihl || n > mtu {
					errs := <-errCh
					errs = append(errs, fmt.Errorf("invalid ipv4 packet size:%d", n))
					errCh <- errs
					return
				}
			case 6:
				n = 40 + int(binary.BigEndian.Uint16(packet[4:6]))
				if n > mtu {
					errs := <-errCh
					errs = append(errs, fmt.Errorf("invalid ipv6 packet size:%d", n))
					errCh <- errs
					return

				}
			default:
				errs := <-errCh
				errs = append(errs, fmt.Errorf("invalid ip version:%d", packet[0]>>4))
				errCh <- errs
				return
			}
			if _, err = io.ReadFull(stream, packet[20:n]); err != nil {
				errs := <-errCh
				errs = append(errs, fmt.Errorf("stream.Read:%w", err))
				errCh <- errs
				return
			}
			buf = batch.swapBuf(buf)
			packet = buf[tunOffset:]
		}
	}()
	wg.Wait()
	return errors.Join(<-errCh...)
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
	zeroSample []byte
	bufPool    chan []byte
	fullCh     chan struct{}
	readyBufs  [][]byte
	mux        sync.Mutex
}

func newBatchWrite(bufSize, batchSize int) *batchWrite {
	buf := make([]byte, batchSize*bufSize)
	b := batchWrite{
		zeroSample: make([]byte, bufSize),
		bufPool:    make(chan []byte, batchSize),
		fullCh:     make(chan struct{}),
		readyBufs:  nil,
	}
	for i := 0; i < batchSize; i++ {
		star, end := i*bufSize, (i+1)*bufSize
		b.bufPool <- buf[star:end:end]
	}
	return &b
}

func (b *batchWrite) swapBuf(in []byte) []byte {
	if in != nil {
		b.mux.Lock()
		b.readyBufs = append(b.readyBufs, in)
		b.mux.Unlock()
	}
	select {
	case buf := <-b.bufPool:
		return buf
	default:
	}
	select {
	case b.fullCh <- struct{}{}:
	default:
	}
	return <-b.bufPool
}

func (b *batchWrite) run(dev tun.Device, d time.Duration) error {
	timer := time.NewTicker(d)
	for {
		select {
		case <-timer.C:
		case <-b.fullCh:
		}
		err := b.write(dev)
		if err != nil {
			return err
		}
	}

}

func (b *batchWrite) write(dev tun.Device) error {
	b.mux.Lock()
	defer b.mux.Unlock()
	if len(b.readyBufs) == 0 {
		return nil
	}
	_, err := dev.Write(b.readyBufs, tunOffset)
	if err != nil {
		return err
	}
	for _, buf := range b.readyBufs {
		buf = append(buf, b.zeroSample[:cap(buf)-len(buf)]...)
		b.bufPool <- buf
	}
	b.readyBufs = b.readyBufs[:0]
	return nil
}

package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/netip"

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
		sizes[i] = bufSize
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

func ForwardStreamToTun(ctx context.Context, dev tun.Device, stream io.Reader) error {
	mtu, err := dev.MTU()
	if err != nil {
		return err
	}

	buf := make([]byte, mtu+tunOffset)
	packet := buf[tunOffset:]
	for {
		_, err := io.ReadFull(stream, packet[:20])
		if err != nil {
			return fmt.Errorf("stream.Read:%w", err)
		}

		var n int
		switch packet[0] >> 4 {
		case 4:
			ihl := int(packet[0]&0x0f) * 4
			n = int(binary.BigEndian.Uint16(packet[2:4]))
			if ihl < 20 || n < ihl || n > mtu {
				return fmt.Errorf("invalid ipv4 packet size:%d", n)
			}
		case 6:
			n = 40 + int(binary.BigEndian.Uint16(packet[4:6]))
			if n > mtu {
				return fmt.Errorf("invalid ipv6 packet size:%d", n)
			}
		default:
			return fmt.Errorf("invalid ip version:%d", packet[0]>>4)
		}
		if _, err = io.ReadFull(stream, packet[20:n]); err != nil {
			return fmt.Errorf("stream.Read:%w", err)
		}
		_, err = dev.Write([][]byte{buf[:tunOffset+n]}, tunOffset)
		if err != nil {
			return fmt.Errorf("tun.Write:%w", err)
		}
	}
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

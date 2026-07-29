package tunnel

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadStreamSkipsPeerPacketsLargerThanLocalMTU(t *testing.T) {
	const mtu = 100
	tooLarge := ipv4Packet(120)
	ipv6 := ipv6Packet(60)
	ipv4 := ipv4Packet(40)
	stream := io.NopCloser(bytes.NewReader(append(append(tooLarge, ipv6...), ipv4...)))
	batch := newBatchWrite(mtu+tunOffset, 4)

	err := readStream(batch, stream, mtu)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("readStream error = %v, want EOF", err)
	}

	for i, want := range [][]byte{ipv6, ipv4} {
		select {
		case got := <-batch.readyQueue:
			got = got[tunOffset:]
			if !bytes.Equal(got, want) {
				t.Errorf("packet %d = %x, want %x", i, got, want)
			}
		default:
			t.Fatalf("packet %d was not queued", i)
		}
	}
	select {
	case got := <-batch.readyQueue:
		t.Fatalf("unexpected packet queued: %x", got[tunOffset:])
	default:
	}
}

func ipv4Packet(size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	p[2] = byte(size >> 8)
	p[3] = byte(size)
	return p
}

func ipv6Packet(size int) []byte {
	p := make([]byte, size)
	p[0] = 0x60
	p[4] = byte((size - 40) >> 8)
	p[5] = byte(size - 40)
	return p
}

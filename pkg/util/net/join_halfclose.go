package net

// Correct bidirectional EOF propagation for raw XTCP QUIC streams. Unlike
// golib/io.Join, one direction reaching EOF must not close the *receive*
// direction: an HTTP/TLS client may send FIN then download megabytes.
import (
	"errors"
	"io"
	"sync"
)

type writeHalfCloser interface {
	CloseWrite() error
}

func JoinHalfClose(a, b io.ReadWriteCloser) (inCount, outCount int64, errs []error) {
	writeA, okA := a.(writeHalfCloser)
	writeB, okB := b.(writeHalfCloser)
	if !okA || !okB {
		_ = a.Close()
		_ = b.Close()
		return 0, 0, []error{errors.New("XTCP half-close requires CloseWrite support on both raw transports")}
	}
	var wg sync.WaitGroup
	var results [2]error
	copyHalf := func(to io.ReadWriteCloser, from io.ReadWriteCloser, dst writeHalfCloser,
		count *int64, index int,
	) {
		defer wg.Done()
		buffer := make([]byte, 64*1024)
		*count, results[index] = io.CopyBuffer(to, from, buffer)
		if results[index] == nil {
			results[index] = dst.CloseWrite()
		}
		if results[index] != nil {
			// Wake the other io.Copy if an endpoint has already failed.
			_ = a.Close()
			_ = b.Close()
		}
	}
	wg.Add(2)
	go copyHalf(a, b, writeA, &inCount, 0)
	go copyHalf(b, a, writeB, &outCount, 1)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	for _, err := range results {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return
}

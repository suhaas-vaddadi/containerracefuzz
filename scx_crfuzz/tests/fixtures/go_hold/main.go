// Fixture for tests/hold.rs. The main goroutine opens os.Args[1] every 100 ms
// (the watched checkpoint); four siblings each write one byte to stdout every
// 100 µs. Bytes reaching stdout while the trigger is held = sibling leak.
package main

import (
	"os"
	"syscall"
	"time"
)

func main() {
	for i := 0; i < 4; i++ {
		go func() {
			b := []byte("x")
			for {
				syscall.Write(1, b)
				time.Sleep(100 * time.Microsecond)
			}
		}()
	}
	for {
		time.Sleep(100 * time.Millisecond)
		if f, err := os.Open(os.Args[1]); err == nil {
			f.Close()
		}
	}
}

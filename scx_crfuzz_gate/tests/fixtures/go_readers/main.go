// Fixture for tests/gate.rs. Goroutines A and B each block in a raw read(2)
// on an inherited pipe (fds 3 and 4) and print their name every time it
// returns. Spinners allocate so GC runs constantly. No LockOSThread: which M
// carries A or B is up to the runtime (M:N).
package main

import "syscall"

func reader(fd int, name string) {
	buf := make([]byte, 1)
	for {
		n, err := syscall.Read(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		if n <= 0 {
			return
		}
		syscall.Write(1, []byte(name+"\n"))
	}
}

func main() {
	for i := 0; i < 4; i++ {
		go func() {
			var keep [][]byte
			for {
				keep = append(keep, make([]byte, 4096))
				if len(keep) > 256 {
					keep = nil
				}
			}
		}()
	}
	go reader(3, "A")
	go reader(4, "B")
	select {}
}

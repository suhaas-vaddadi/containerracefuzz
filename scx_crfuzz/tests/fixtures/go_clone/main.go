// Fixture for the clone-hold test: 8 goroutines read os.Args[1] in a loop
// (blocking syscalls make the runtime start new Ms, i.e. clone) while
// allocating and forcing GCs (stop-the-world), and one goroutine forks
// /bin/true 5 times in sequence, so process clones (Go's raw vfork, restarted
// by SIGURG) happen while the runtime makes Ms. Exits 0 when all are done.
package main

import (
	"os"
	"os/exec"
	"runtime"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var sink [][]byte
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := os.ReadFile(os.Args[1]); err != nil {
					panic(err)
				}
				mu.Lock()
				sink = append(sink, make([]byte, 1<<20))
				if len(sink) > 16 {
					sink = sink[:0]
				}
				mu.Unlock()
				if j%10 == 0 {
					runtime.GC()
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			if err := exec.Command("/bin/true").Run(); err != nil {
				panic(err)
			}
		}
	}()
	wg.Wait()
}

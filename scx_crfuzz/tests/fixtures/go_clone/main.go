// Fixture for the clone-hold spike: 8 goroutines read os.Args[1] in a loop
// (blocking syscalls make the runtime start new Ms, i.e. clone) while
// allocating and forcing GCs (stop-the-world). Exits 0 when all are done.
package main

import (
	"os"
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
	wg.Wait()
}

// Fixture for tests/sensor.rs: the main goroutine blocks on a channel forever;
// one goroutine opens os.Args[1] (the watched checkpoint) once. Every other
// runtime thread (sysmon, idle Ms) is left to the runtime.
package main

import "os"

func main() {
	ch := make(chan struct{})
	go func() {
		if f, err := os.Open(os.Args[1]); err == nil {
			f.Close()
		}
		<-ch
	}()
	<-ch
}

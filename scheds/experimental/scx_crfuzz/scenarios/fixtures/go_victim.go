// SPDX-License-Identifier: GPL-2.0
//
// The check-then-use victim again, this time in Go -- the runtime that makes
// the whole thread-group problem real.
//
// threaded_victim.c proves the point with pthreads, but the actual targets
// (runc, containerd) are Go, and Go's scheduler is not pthreads. Goroutines
// multiplex onto OS threads (Ms), and when a goroutine blocks in a syscall the
// runtime's sysmon hands its work to another M -- spinning up a fresh OS
// thread if it has to. Blocking one thread in a seccomp notification is
// therefore not a neutral act: it is the signal that provokes the runtime into
// creating more parallelism, which is exactly the parallelism a hold is
// supposed to suppress.
//
// So the siblings here each call runtime.LockOSThread. That pins every one of
// them to its own M, which is the faithful analogue of what a busy Go program
// looks like when the engine tries to hold it, and it makes "how many OS
// threads should have been frozen" a number the test can state rather than
// hope for.
//
// The main goroutine is locked too, so the check/use pair runs on one known
// thread and stops at the same structural checkpoints victim.c does.
//
// Build with CGO_ENABLED=0 (see the Makefile): a cgo binary drags in the
// dynamic loader, whose own path-touching syscalls before main() are all
// checkpoints in the section 4.2 structural set.
package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
)

// syscall.AT_FDCWD / AT_SYMLINK_NOFOLLOW are not exported uniformly across
// GOOS, so they are spelled out here rather than guessed at.
const (
	unixAtFdcwd     = -100
	symlinkNofollow = 0x100
)

// How many sibling OS threads to keep running. More than one so the test is
// measuring a thread *group* rather than a single unlucky thread.
const siblings = 4

// The sibling loop writes to an fd opened once, up front, so it only ever
// makes write(2) calls. write is not in the structural syscall set, so a
// sibling never trips a checkpoint of its own -- anything in the progress file
// is unambiguously "a thread that should have been held was running".
func sibling(fd int, stop <-chan struct{}) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		select {
		case <-stop:
			return
		default:
		}
		syscall.Write(fd, []byte("."))
		time.Sleep(time.Millisecond)
	}
}

func say(s string) {
	syscall.Write(1, []byte(s))
}

func main() {
	if len(os.Args) < 3 {
		say("VERDICT:usage\n")
		os.Exit(2)
	}
	path, progress := os.Args[1], os.Args[2]

	// Keep the main goroutine on one OS thread, so the check and the use are
	// made by the same task the engine holds.
	runtime.LockOSThread()

	pfd, err := syscall.Open(progress, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC, 0644)
	if err != nil {
		say("VERDICT:progress-open-failed\n")
		os.Exit(1)
	}

	stop := make(chan struct{})
	for i := 0; i < siblings; i++ {
		go sibling(pfd, stop)
	}

	// Let the siblings get onto their own Ms, so a test sampling the progress
	// file at the first checkpoint is measuring genuinely running threads
	// rather than ones that have not started yet.
	time.Sleep(50 * time.Millisecond)

	// CHECK -- fstatat with AT_SYMLINK_NOFOLLOW, the same first structural
	// checkpoint victim.c stops at. On arm64 this is the newfstatat syscall.
	var st syscall.Stat_t
	if err := syscall.Fstatat(unixAtFdcwd, path, &st, symlinkNofollow); err != nil {
		say("VERDICT:check-failed\n")
		os.Exit(1)
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		say("VERDICT:refused-symlink\n")
		close(stop)
		os.Exit(0)
	}

	// USE -- by name, not by anything the check returned. The flaw.
	fd, err := syscall.Openat(unixAtFdcwd, path, syscall.O_RDONLY, 0)
	if err != nil {
		say("VERDICT:open-failed\n")
		os.Exit(1)
	}
	buf := make([]byte, 64)
	n, _ := syscall.Read(fd, buf)
	syscall.Close(fd)
	if n < 0 {
		n = 0
	}
	out := string(buf[:n])
	for i, c := range out {
		if c == '\n' {
			out = out[:i]
			break
		}
	}
	close(stop)
	say(fmt.Sprintf("VERDICT:read=%s\n", out))
}

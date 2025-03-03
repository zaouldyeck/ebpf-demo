package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type event struct {
	PID      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("opensnoop.o")
	if err != nil {
		log.Fatalf("failed to load collection spec: %v", err)
	}

	// Hardcode kernel version (e.g., 6.12.5 = 0x060c05)
	for _, progSpec := range spec.Programs {
		if progSpec.Type == ebpf.Kprobe {
			progSpec.KernelVersion = 0x060c05 // 6.12.5
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to load collection: %v", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["trace_openat"]
	if !ok {
		log.Fatalf("program 'trace_openat' not found")
	}

	kp, err := link.Kprobe("sys_enter_openat", prog, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		log.Fatalf("map 'events' not found")
	}

	reader, err := perf.NewReader(eventsMap, 4096)
	if err != nil {
		log.Fatalf("failed to create perf reader: %v", err)
	}
	defer reader.Close()

	log.Println("Listening for openat events... (press Ctrl+C to exit)")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-sigCh:
			log.Println("Exiting...")
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("error reading perf event: %v", err)
				continue
			}

			var evt event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
				log.Printf("failed to parse event: %v", err)
				continue
			}

			comm := string(bytes.Trim(evt.Comm[:], "\x00"))
			filename := string(bytes.Trim(evt.Filename[:], "\x00"))
			fmt.Printf("PID: %d, Process: %s, Opened File: %s\n", evt.PID, comm, filename)
		}
	}
}

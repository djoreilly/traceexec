package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"log/slog"
	"slices"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

//go:embed main.bpf.o
var bpfCode []byte

type Event struct {
	Pid      uint32
	Ppid     uint32
	Comm     [16]byte
	PathSize uint32
	ArgvSize uint32
}

func main() {
	verbose := flag.Bool("v", false, "enable libbpf debug logging")
	flag.Parse()
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(level int, msg string) {
			switch level {
			case bpf.LibbpfInfoLevel:
				slog.Info(msg)
			case bpf.LibbpfWarnLevel:
				slog.Warn(msg)
			case bpf.LibbpfDebugLevel:
				slog.Debug(msg)
			}
		},
	})

	// bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	bpfModule, err := bpf.NewModuleFromBuffer(bpfCode, "")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		_, err = prog.AttachGeneric()
		if err != nil {
			panic(err)
		}
	}

	eventsChannel := make(chan []byte)
	ringBuf, err := bpfModule.InitRingBuf("rb", eventsChannel)
	if err != nil {
		panic(err)
	}

	ringBuf.Poll(300)
	defer ringBuf.Close()

	var event Event
	eventSize := uint32(unsafe.Sizeof(event))

	for rawData := range eventsChannel {
		eventData := bytes.NewBuffer(rawData[:eventSize])
		if err := binary.Read(eventData, binary.NativeEndian, &event); err != nil {
			slog.Warn("reading data:", "error", err)
			continue
		}
		argsEnd := eventSize + event.ArgvSize
		pathEnd := argsEnd + event.PathSize
		slog.Info("Event", "PID", event.Pid, "PPID", event.Ppid,
			"Comm", unix.ByteSliceToString(event.Comm[:]),
			"Path", parsePath(rawData[argsEnd:pathEnd]),
			"Args", bytes.ReplaceAll(rawData[eventSize:argsEnd], []byte{0x00}, []byte(" ")),
		)
	}
}

func parsePath(s []byte) []byte {
	if s[0] == '/' {
		return bytes.TrimSuffix(s, []byte{0x00})
	}
	// If prog was passed to exec as a relative path, then
	// the bpf program provides the path components in reverse
	// order like: prog\0dir2\0dir1\0mnt\0
	components := bytes.Split(s, []byte{0x00})
	slices.Reverse(components)
	return bytes.Join(components, []byte("/"))
}

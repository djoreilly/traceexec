package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"log/slog"
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
	Path     [512]byte
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
		args := bytes.ReplaceAll(rawData[eventSize:eventSize+event.ArgvSize], []byte{0x00}, []byte(" "))
		slog.Info("Event", "PID", event.Pid, "PPID", event.Ppid,
			"Comm", unix.ByteSliceToString(event.Comm[:]),
			"Path", unix.ByteSliceToString(event.Path[:]),
			"Args", args)
	}
}

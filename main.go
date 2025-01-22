package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"log/slog"
	"path/filepath"
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
	Uid      uint32
	Comm     [16]byte
	PathSize uint32
	ArgvSize uint32
	CwdSize  uint32
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
		cwdEnd := pathEnd + event.CwdSize

		cwd := cwdFromPathParts(rawData[pathEnd:cwdEnd])
		path := unix.ByteSliceToString(rawData[argsEnd:pathEnd])
		if path[0] != '/' {
			path = filepath.Join(cwd, path)
		}

		slog.Info("Event", "PID", event.Pid, "PPID", event.Ppid, "Uid", event.Uid,
			"Comm", unix.ByteSliceToString(event.Comm[:]),
			"Path", path,
			"Args", bytes.ReplaceAll(rawData[eventSize:argsEnd], []byte{0x00}, []byte(" ")),
			"Cwd", cwd,
		)
	}
}

func cwdFromPathParts(s []byte) string {
	if len(s) == 0 {
		return "/"
	}
	// the bpf program provides the cwd path components in reverse
	// order and \0 delimited. Reverse and replace all \0 with /.
	// e.g. dir2\0dir1\0mnt\0 -> /mnt/dir1/dir2

	components := bytes.Split(s, []byte{0x00})
	slices.Reverse(components)
	return string(bytes.Join(components, []byte("/")))
}

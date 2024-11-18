# traceexec
Example eBPF to trace the execve system call.

This example traces `tracepoint/sched/sched_process_exec` because tracing `tracepoint/syscalls/sys_enter_execve` is not reliable - see [this](https://mozillazg.com/2024/03/ebpf-tracepoint-syscalls-sys-enter-execve-can-not-get-filename-argv-values-case-en.html) for why.

It's built using [libbpfgo](https://github.com/aquasecurity/libbpfgo) which is a thin golang wrapper around the C [libbpf](https://docs.ebpf.io/ebpf-library/libbpf/). Libbpf is a git submodule in the repo so it can be built and the eBPF program statically linked to it. The resulting object is embedded in the golang binary and the target machines don't require any dependencies. Also [CORE](https://docs.ebpf.io/concepts/core/) allows the binary to work across kernel versions.

The code to find the full path when a relative path is passed to execve is based on [this.](https://github.com/aquasecurity/tracee/blob/a6118678c6908c74d6ee26ca9183e99932d098c9/pkg/ebpf/c/common/filesystem.h#L160)

Most of the [Makefile](Makefile) is explained [here](https://nakryiko.com/posts/libbpf-bootstrap/#makefile).

## Building
### openSUSE Leap 15.6
```
$ sudo zypper install git make libelf-devel bpftool clang go1.23
```
Path to `/usr/sbin` is needed for `bpftool`

```
$ export PATH=$PATH:/usr/sbin
$ make
```
### Debian 12
For golang see [here](https://go.dev/doc/install).
```
$ sudo apt install git make libelf-dev bpftool clang
$ make
```

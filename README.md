# snooptop

`snooptop` is an eBPF-based Linux utility that traces process executions (`execve` syscalls) in real-time. It provides a terminal UI and a JSON streaming mode for pipeline integration.

## Requirements
* Linux kernel 5.8+ (requires `CONFIG_DEBUG_INFO_BTF=y`)
* Root privileges (required for eBPF tracepoints)
* Build dependencies: `cmake`, `clang`, `libbpf-dev`, `bpftool`

## Build
```bash
git clone https://github.com/th3wst/snooptop.git
cd snooptop
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Usage
sudo ./snooptop

## JSON Stream
Bypass the TUI to output raw JSON lines for scripting, logging, or piping.
```
sudo ./snooptop --json
sudo ./snooptop -j | jq
sudo ./snooptop -j | grep "nginx"
```

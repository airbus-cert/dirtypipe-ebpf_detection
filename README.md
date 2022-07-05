# dirtypipe-ebpf_detection -- Dirtypipe detection tool

This program was made to detect Dirty Pipe exploitation attempts thanks to eBPF. It also monitors nonvulnerable kernels and docker containers.

![](/.images/088d790795eb65a66c268d61039feeea5455bae6.gif)

:flight_departure: If you want more details on how it works please read the [blog](https://skyblue.team/posts/dirtypipe-ebpf-detection/) post ! :flight_arrival:

## How does it works?

**Default execution:**

```bash
sudo ./bin/dirtypipe_detection
```

**Debug mode:**

> Show libbpf logs on execution

```bash
sudo ./bin/dirtypipe_detection --debug
```

**Daemon mode:**

> Run program as daemon and send alerts over syslog

```bash
sudo ./bin/dirtypipe_detection --daemon
```

## How to build?

### Debian

```bash
sudo apt install git make pkg-config libelf-dev clang-11 libc6-dev-i386 bpftool -y
git clone https://github.com/airbus-cert/dirtypipe-ebpf_detection
cd ./dirtypipe-ebpf_detection/src/
make
```

### Ubuntu

```bash
sudo apt install git make pkg-config libelf-dev clang-11 libc6-dev-i386 linux-tools-common linux-tools-$(uname -r) -y
git clone https://github.com/airbus-cert/dirtypipe-ebpf_detection
cd ./dirtypipe-ebpf_detection/src/
make
```

## Credits and References

Read the original [blog](https://dirtypipe.cm4all.com/) on Dirtypipe from max.kellermann@ionos.com

Read an interesting strategy from [Datadog](https://www.datadoghq.com/blog/dirty-pipe-vulnerability-overview-and-remediation/) team

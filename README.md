# eBPF TCP Packet Size Monitoring

This eBPF program monitors and observes the TCP send/receive data packet sizes for a specific process identified by its PID. The program uses Python 3 and BCC (BPF Compiler Collection) to achieve this. The usage involves executing the program using `sudo` with a specified PID.

## Requirements

- Python 3
- BCC (BPF Compiler Collection)
- Root privileges (to load eBPF programs)

## Installation

### Installing Python 3

You can install Python 3 using your package manager. For example, on CentOS:

```sh
sudo yum install python3
```

### Installing BCC

To install BCC, you need to add the EPEL repository and then install it. Here is how you can do it on CentOS:

```sh
# Add EPEL repository
sudo yum install epel-release

# Install BCC and its Python bindings
sudo yum install bcc bcc-tools python3-bcc
```

## Usage

execute it with root privileges, passing the PID of the process you want to monitor:

```sh
sudo python3 test.py <pid>
```

### Execution Output

Upon executing the above command, you will first see the initialization and attachment messages:

```
start, pid = xxx
str_replace remove ok
BPF initialization success
Attached kprobe for tcp_sendmsg
Attached kprobe for tcp_cleanup_rbuf
```

As the process with the specified PID triggers TCP send and receive data packets, the script will output the cumulative packet sizes at one-second intervals as shown below:

```
pid: xxx time: 2024-12-04 11:45:18 type: sendMsg size: 109816578048
pid: xxx time: 2024-12-04 11:45:18 type: recvMsg size: 34
pid: xxx time: 2024-12-04 11:45:19 type: sendMsg size: 109816578048
pid: xxx time: 2024-12-04 11:45:19 type: recvMsg size: 34
pid: xxx time: 2024-12-04 11:45:20 type: sendMsg size: 110061158400
pid: xxx time: 2024-12-04 11:45:20 type: recvMsg size: 62
pid: xxx time: 2024-12-04 11:45:21 type: sendMsg size: 110061158400
pid: xxx time: 2024-12-04 11:45:21 type: recvMsg size: 62
```

## Notes

- The script uses eBPF to hook into kernel functions `tcp_sendmsg` and `tcp_cleanup_rbuf` to monitor TCP send and receive data packet sizes for the specified process.
- Ensure you have the necessary permissions to run eBPF programs, which typically requires root privileges.
- The monitored process must be actively sending or receiving TCP data for the script to capture and display information.

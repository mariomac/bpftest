# Tests with eBPF and Docker

To build it:

```
docker build . --tag=bpftest:latest
```

This works on Centos8:

```
docker run --name bpftest -it --rm --privileged --network host bpftest:latest
```
# Tests with eBPF and Docker

To build it:

```
docker build . --tag=quay.io/mmaciasl/netdump:latest
```

This works on Centos8:

```
docker run --name bpftest -it --rm --privileged --network host bpftest:latest
```

To deploy it in K8s:

```
oc apply -f k8s-daemonset.yml
oc logs -f -l app=netdump | uniq -u
```

## TODO

* BTF CO-RE distribution
* Auto-detect interfaces
* Properly work with OVNKubernetes CNI type
* 
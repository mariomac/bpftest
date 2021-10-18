FROM centos:8

RUN yum -y install epel-release
RUN yum update -y
RUN yum install -y bpftrace kernel-headers kernel-cross-headers iperf3 netperf

RUN yum -y clean all
RUN rm -rf /var/cache/dnf

CMD ["/bin/bash"]
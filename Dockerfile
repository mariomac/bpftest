FROM centos:8

RUN yum -y install epel-release
RUN yum update -y
RUN yum groupinstall -y "Development tools"
RUN yum install -y elfutils-libelf-devel cmake3 git bison flex ncurses-devel golang iperf3 netperf
RUN yum install -y golang
RUN yum install -y llvm-toolset llvm-devel llvm-static clang-devel
RUN yum install -y python3-netaddr python3-pyroute2 python3
RUN ln -s /usr/bin/python3.6 /usr/bin/python
RUN yum -y install kernel-devel kernel-headers kernel-modules kernel-cross-headers

RUN git clone --branch v0.22.0 --single-branch --depth 1 https://github.com/iovisor/bcc.git
RUN mkdir /bcc/build
WORKDIR /bcc/build
RUN cmake3 ..
RUN make
RUN make install

WORKDIR /code
COPY . .
RUN go build -o /netdump src/netdump.go
COPY src/netdump.bcc.c /netdump.bcc.c

WORKDIR /

# TODO Clean other unneeded yum packages
RUN rm -rf /code
RUN rm -rf /bcc

CMD ["/netdump"]
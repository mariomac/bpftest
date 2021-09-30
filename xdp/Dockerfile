FROM centos:8

RUN yum update -y
RUN yum install -y wireshark-cli xdp-tools

COPY run.sh /run.sh

CMD ["sh", "/run.sh"]
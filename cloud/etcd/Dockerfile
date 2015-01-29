FROM ubuntu
RUN \
 sed 's/main$/main universe/' -i /etc/apt/sources.list && \
 apt-get update && \
 env DEBIAN_FRONTEND=noninteractive apt-get install -y curl
RUN \
 cd /tmp && \
 (curl -L  https://github.com/coreos/etcd/releases/download/v0.4.6/etcd-v0.4.6-linux-amd64.tar.gz | tar -xz) && \
 mkdir -p /opt/etcd/bin && \
 cp -v /tmp/etcd-v0.4.6-linux-amd64/etcd /opt/etcd/bin && \
 cp -v /tmp/etcd-v0.4.6-linux-amd64/etcdctl /opt/etcd/bin && \
 rm -rf /tmp/etcd-v0.4.6-linux-amd64
WORKDIR /opt/etcd
VOLUME ["/opt/etcd/data"]
CMD MY_IP=$(awk "/${HOSTNAME}/ {print \$1}" < /etc/hosts) && \
    echo "My IP: ${MY_IP}" && \
    echo "My Discovery: ${DISCOVERY}" && \
    /opt/etcd/bin/etcd --discovery="${DISCOVERY}" \
          --name=${HOSTNAME} \
          --addr=${MY_IP}:4001 \
          --peer-addr=${MY_IP}:7001 \
          --data-dir=/opt/etcd/data \
EXPOSE 4001 7001


FROM ubuntu
RUN echo 'Building new SuperDuper Docker image...'
COPY test/testdata/ca-cert.pem /tmp/
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    apt-add-repository -y ppa:jbboehr/coreos && \
    apt-get update && \
    apt-get install -qqy \
        ca-certificates \
        etcdctl \
        libevent-core-2.0.5 \
        libevent-extra-2.0.5 \
        libevent-pthreads-2.0.5 \
        libgflags2 \
        libgoogle-glog0 \
        libjson-c2 \
        libldns1 \
        libprotobuf8
RUN update-ca-certificates && \
    cat /etc/ssl/certs/* /tmp/ca-cert.pem > /usr/local/etc/ctlog_ca_roots.pem
RUN groupadd -r ctlog && useradd -r -g ctlog ctlog
RUN mkdir /mnt/ctlog
COPY cpp/server/ct-server /usr/local/bin/
COPY test/testdata/ct-server-key.pem /usr/local/etc/
VOLUME /mnt/ctlog
CMD cd /mnt/ctlog/ && \
    if [ ! -d logs ]; then mkdir logs; fi && \
    /usr/local/bin/ct-server \
        --port=6962 \
        --key=/usr/local/etc/ct-server-key.pem \
        --trusted_cert_file=/usr/local/etc/ctlog_ca_roots.pem \
        --stderrthreshold=0 \
        --log_dir=/mnt/ctlog/logs \
        --tree_signing_frequency_seconds=60 \
        --sqlite_db=/mnt/ctlog/sqlite.db \
        --v=1
EXPOSE 6962

FROM prom/prometheus
ENTRYPOINT echo "Config: ${PROMETHEUS_CONFIG}" && \
    cat ${PROMETHEUS_CONFIG} && \
    echo "Storage: ${PROMETHEUS_STORAGE}" && \
    /go/src/github.com/prometheus/prometheus/prometheus \
      -logtostderr \
      -config.file=${PROMETHEUS_CONFIG} \
      -storage.local.path=${PROMETHEUS_STORAGE} \
      -web.console.libraries=/go/src/github.com/prometheus/prometheus/console_libraries \
      -web.console.templates=/go/src/github.com/prometheus/prometheus/consoles
CMD []

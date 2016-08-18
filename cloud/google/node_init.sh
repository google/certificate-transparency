#! /bin/bash
export DATA_DIR=/data
export DATA_DEV=/dev/disk/by-id/google-persistent-disk-1

sudo mkdir ${DATA_DIR}
sudo /usr/share/google/safe_format_and_mount \
  -m "mkfs.ext4 -F" ${DATA_DEV} ${DATA_DIR}

# Install the Stackdriver agent to pass metrics to Stackdriver Monitoring.
AGENT_INSTALL_SCRIPT="stack-install.sh"
EXPECTED_SHA256="3d298c1e8a06efa08bbf237cd663710ae124c631fc976f70098f0fde642bb29b  ./${AGENT_INSTALL_SCRIPT}"
curl -O https://repo.stackdriver.com/${AGENT_INSTALL_SCRIPT}
if ! echo "${EXPECTED_SHA256}" | sha256sum --quiet -c; then
  echo "Got ${AGENT_INSTALL_SCRIPT} with sha256sum "
  sha256sum ./${AGENT_INSTALL_SCRIPT}
  echo "But expected:"
  echo "${EXPECTED_SHA256}"
  echo "${AGENT_INSTALL_SCRIPT} may have been updated, verify the new sum at"
  echo "https://cloud.google.com/monitoring/agent/install-agent and update"
  echo "this script with the new sha256sum if necessary."
  exit 1
fi

sudo bash ./${AGENT_INSTALL_SCRIPT} --write-gcm

# Install google-fluentd which pushes application log files up into the Google
# Cloud Logs Monitor.
AGENT_INSTALL_SCRIPT="install-logging-agent.sh"
EXPECTED_SHA256="07ca6e522885b9696013aaddde48bf2675429e57081c70080a9a1364a411b395  ./${AGENT_INSTALL_SCRIPT}"
curl -sSO https://dl.google.com/cloudagents/${AGENT_INSTALL_SCRIPT}
if ! echo "${EXPECTED_SHA256}" | sha256sum --quiet -c; then
  echo "Got ${AGENT_INSTALL_SCRIPT} with sha256sum "
  sha256sum ./${AGENT_INSTALL_SCRIPT}
  echo "But expected:"
  echo "${EXPECTED_SHA256}"
  echo "${AGENT_INSTALL_SCRIPT} may have been updated, verify the new sum at"
  echo "https://cloud.google.com/logging/docs/agent/installation and update"
  echo "this script with the new sha256sum if necessary."
  exit 1
fi

# TODO(robpercival): For CT mirrors, the path below should be "/data/ctmirror/",
# not "/data/ctlog/".
sudo bash ./${AGENT_INSTALL_SCRIPT}
sudo cat > /etc/google-fluentd/config.d/ct-info.conf <<EOF
<source>
  type tail
  format none
  path /data/ctlog/logs/ct-server.*.INFO.*
  pos_file /data/ctlog/logs/ct-server.INFO.pos
  read_from_head true
  tag ct-info
</source>
<source>
  type tail
  format none
  path /data/ctlog/logs/ct-server.*.ERROR.*
  pos_file /data/ctlog/logs/ct-server.ERROR.pos
  read_from_head true
  tag ct-warn
</source>
<source>
  type tail
  format none
  path /data/ctlog/logs/ct-server.*.WARNING.*
  pos_file /data/ctlog/logs/ct-server.WARNING.pos
  read_from_head true
  tag ct-warn
</source>
<source>
  type tail
  format none
  path /data/ctlog/logs/ct-server.*.FATAL.*
  pos_file /data/ctlog/logs/ct-server.FATAL.pos
  read_from_head true
  tag ct-error
</source>
EOF
sudo service google-fluentd restart
# End google-fluentd stuff

cat > /etc/logrotate.d/docker <<EOF
/var/log/docker.log {
  rotate 7
  daily
  compress
  size=1M
  missingok
  delaycompress
  copytruncate
}
EOF

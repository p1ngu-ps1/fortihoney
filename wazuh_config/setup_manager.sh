#!/bin/sh
# This script runs inside the Wazuh Manager container to configure the FortiHoney log source

LOG_FILE="/var/ossec/logs/fortihoney/fortihoney.json"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

if ! grep -q "$LOG_FILE" "$OSSEC_CONF"; then
    echo "Configuring Wazuh to read FortiHoney logs..."
    sed -i '/<\/ossec_config>/i \
  <localfile> \
    <log_format>json</log_format> \
    <location>'"$LOG_FILE"'</location> \
  </localfile>' "$OSSEC_CONF"
    /var/ossec/bin/ossec-control restart
fi
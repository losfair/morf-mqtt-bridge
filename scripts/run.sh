#!/bin/bash

set -e

cd "$(dirname $0)/.."
cargo build --release
./target/release/morf-mqtt-bridge \
  --secret-key <(base64 -d < ./scripts/testkey/server.priv) \
  --downlink 127.0.0.1:7891 \
  --uplink-local 127.0.0.1:0 \
  --uplink-remote 127.0.0.1:7890 \
  --mqtt-client-id morf-mqtt-bridge-test \
  --mqtt-server 192.168.207.12:9783 \
  --mqtt-tls \
  --mqtt-tls-server-name emqx.y.invariant.cn \
  --db ./test.db

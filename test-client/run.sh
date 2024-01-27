#!/bin/bash

set -e

cargo build --release

./target/release/test-client \
  --device-secret-key <(base64 -d < ../scripts/testkey/device.priv) \
  --server-public-key <(base64 -d < ../scripts/testkey/server.pub) \
  --local 127.0.0.1:7890 \
  --remote 127.0.0.1:7891

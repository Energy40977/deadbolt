#!/usr/bin/env bash
set -euo pipefail

# deadbolt-expect DB-INF-002:high
docker run -d -p 0.0.0.0:5432:5432 postgres:16

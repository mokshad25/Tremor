#!/bin/bash
# LocalStack init script — runs when LocalStack is ready.
# Creates the SNS topic and CloudWatch log group that TREMOR expects.

set -euo pipefail

echo "=== TREMOR LocalStack Init ==="

# Create SNS topic
awslocal sns create-topic --name tremor-alerts
echo "✓ SNS topic 'tremor-alerts' created"

# Create CloudWatch log group
awslocal logs create-log-group --log-group-name /tremor/alerts
awslocal logs create-log-stream --log-group-name /tremor/alerts --log-stream-name default
echo "✓ CloudWatch log group '/tremor/alerts' created"

echo "=== TREMOR LocalStack Init Complete ==="

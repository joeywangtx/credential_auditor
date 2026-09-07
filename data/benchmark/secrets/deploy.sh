#!/bin/bash
export GITHUB_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8
aws s3 sync ./dist s3://prod-assets --acl public-read
curl -H "Authorization: Bearer sk_live_51Hxxk2eZvKYlo2C0AbCdEfGhIjKl" https://api.stripe.com/v1/charges
echo done

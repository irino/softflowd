#!/bin/sh
# Pulls a Docker official image: from Docker Hub first and, when Docker Hub
# does not deliver it (unauthenticated pull rate limit on the shared runner
# IPs, outage), from the AWS ECR Public mirror of the official images.
#
# usage: pull-image.sh NAME:TAG
#
# The reference that was pulled is written to $GITHUB_OUTPUT as "ref=..."
# (to the standard output outside GitHub Actions).

set -u

if [ $# -ne 1 ]; then
  echo "usage: $0 NAME:TAG" >&2
  exit 2
fi

image=$1
hub="docker.io/library/$image"
ecr="public.ecr.aws/docker/library/$image"

# try_pull REFERENCE ATTEMPTS: pull with a growing pause between attempts.
try_pull() {
  ref=$1
  attempts=$2
  n=1
  while [ "$n" -le "$attempts" ]; do
    echo "docker pull $ref (attempt $n of $attempts)" >&2
    if docker pull "$ref"; then
      return 0
    fi
    if [ "$n" -lt "$attempts" ]; then
      sleep $((n * 15))
    fi
    n=$((n + 1))
  done
  return 1
}

if try_pull "$hub" 2; then
  ref=$hub
else
  echo "::warning::Docker Hub did not deliver $image, falling back to AWS ECR Public" >&2
  if try_pull "$ecr" 3; then
    ref=$ecr
  else
    echo "::error::could not pull $image from Docker Hub or from AWS ECR Public" >&2
    exit 1
  fi
fi

echo "using $ref" >&2
echo "ref=$ref" >> "${GITHUB_OUTPUT:-/dev/stdout}"

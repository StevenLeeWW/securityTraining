#!/bin/bash

docker compose down
docker compose build web-security-lab
docker compose up -d
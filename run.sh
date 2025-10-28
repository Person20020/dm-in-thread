#!/bin/bash

if [ "$(basename "$PWD")" != "dm-in-thread" ]; then
   echo "Error: This script must be run from within the 'dm-in-thread' directory."
   exit 1
fi

. ./venv/bin/activate
. .env

gunicorn -w 2 \
    -b 127.0.0.1:"$PORT" \
    --access-logfile .logs/access.log \
    --error-logfile .logs/error.log \
    app:app

#!/bin/bash
# Double-click this file in Finder to launch ATXQU.
# It starts the local server and opens the dashboard in your browser.
cd "$(dirname "$0")"
echo "Starting ATXQU…"
exec /usr/bin/python3 server.py

#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: ./mock_backend.sh <node_id> [port]"
    echo "Example: ./mock_backend.sh server1 8080"
    exit 1
fi

NODE_ID=$1
PORT=${2:-8080}

echo "[*] Trying to connect to C program on 127.0.0.1:$PORT..."

# Sử dụng nc (netcat) để gửi chuỗi ID qua TCP Socket
echo -n "$NODE_ID" | nc -q 1 127.0.0.1 $PORT

if [ $? -eq 0 ]; then
    echo -e "\n[*] Connected! Sent node_id: '$NODE_ID' successfully."
else
    echo -e "\n[-] Connection refused! Make sure your C program is running and listening on port $PORT."
fi

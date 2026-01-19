#!/bin/bash

# Test script to help debug the TUI

echo "Starting alice..."
go run . --id alice >/tmp/alice.log 2>&1 &
ALICE_PID=$!

sleep 2

echo "Starting bob..."
go run . --id bob >/tmp/bob.log 2>&1 &
BOB_PID=$!

sleep 2

# Cleanup
kill $ALICE_PID $BOB_PID 2>/dev/null
wait $ALICE_PID $BOB_PID 2>/dev/null

echo "Test completed"

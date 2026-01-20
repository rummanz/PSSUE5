#!/bin/bash
# Copyright Epic Games, Inc. All Rights Reserved.

# Move to the script's directory
cd "$(dirname "$0")" || exit

# Move to the root of the Matchmaker directory (3 levels up from platform_scripts/bash)
cd ../.. || exit

# Run the Matchmaker using the system's node
echo "Starting Matchmaker..."
node matchmaker.js

#!/bin/bash

CONNECTED_DEVICE=$(bluetoothctl info | grep "Device" | awk '{print $2}')

if [ -z "$CONNECTED_DEVICE" ]; then
    echo "No connected bluetooth device found!"
else
    echo "Disconnecting device: $CONNECTED_DEVICE"
    bluetoothctl disconnect $CONNECTED_DEVICE
    echo "✅ Device disconnected successfully!"
fi

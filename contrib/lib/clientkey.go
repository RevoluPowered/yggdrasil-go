package main

// clientKey is compiled into all something.chat binaries.
// It prevents vanilla Yggdrasil nodes from peering with our network.
// This is NOT a secret — it is a compiled-in constant for network segmentation.
const clientKey = "somethingchat-v1-k8x2mQ9pLwR7nTfY3hBvJ6dA"

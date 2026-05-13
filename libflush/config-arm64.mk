# Native Linux ARM64 build for Raspberry Pi 3B (Cortex-A53)
# Android NDK section removed — using system gcc

CC      = gcc
CFLAGS += -march=armv8-a -fPIE -O2 -Wall
LDFLAGS += -fPIE -lpthread

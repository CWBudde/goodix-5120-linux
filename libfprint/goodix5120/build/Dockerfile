# Build environment for the goodix5120 bundle: Ubuntu 26.04, the release the
# prebuilt library targets, with libfprint's build dependencies and OpenCV for
# SIGFM. build-bundle.sh runs inside it, with --network none.
FROM ubuntu:26.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates git patch meson ninja-build pkg-config \
      libglib2.0-dev libgusb-dev libusb-1.0-0-dev libssl-dev libpixman-1-dev libcairo2-dev patchelf \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libopencv-dev=4.10.0+dfsg-7ubuntu5 \
    && rm -rf /var/lib/apt/lists/*

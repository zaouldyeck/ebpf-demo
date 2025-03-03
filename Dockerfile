#############################
# Stage 1: Build Kernel Headers
#############################
FROM debian:buster-slim AS kernel-headers

# Install tools for downloading and building headers.
RUN apt-get update && apt-get install -y wget xz-utils make gcc bc rsync

WORKDIR /usr/src
# Download the Linux kernel source for version 6.12.5.
RUN wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.5.tar.xz && \
    tar -xf linux-6.12.5.tar.xz && \
    rm linux-6.12.5.tar.xz

WORKDIR /usr/src/linux-6.12.5
# Clean the source tree.
RUN make mrproper
# Install the headers to a designated directory.
RUN make headers_install INSTALL_HDR_PATH=/usr/src/linux-headers

#############################
# Stage 2: Build eBPF Object and Go Binary
#############################
FROM golang:1.23 AS builder

WORKDIR /workspace

# Add LLVM apt repository to install clang-16 and llvm-16.
RUN apt-get update && apt-get install -y wget gnupg lsb-release && \
    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    echo "deb http://apt.llvm.org/$(lsb_release -sc)/ llvm-toolchain-$(lsb_release -sc)-16 main" > /etc/apt/sources.list.d/llvm.list && \
    apt-get update && \
    apt-get install -y clang-16 llvm-16 libelf-dev libc6-dev build-essential

# Copy the kernel headers from Stage 1.
COPY --from=kernel-headers /usr/src/linux-headers /usr/src/linux-headers
# Tell clang where to find the kernel headers.
ENV C_INCLUDE_PATH=/usr/src/linux-headers

# Copy Go module files and download dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code (both Go and C files).
COPY . .

# Compile the eBPF C program, specifying the include paths.
RUN clang-16 -O2 -g -Wall -target bpf -nostdinc -D__TARGET_ARCH_arm64 \
    -isystem `clang-16 -print-resource-dir`/include \
    -isystem /usr/src/linux-headers/include \
    -isystem /usr/src/linux-headers/include/uapi \
    -I. \
    -c opensnoop.c -o opensnoop.o

# Build the Go binary (ensuring CGO is enabled for eBPF support).
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o opensnoop .

#############################
# Stage 3: Create the Runtime Image
#############################
FROM debian:buster

# Install runtime dependencies.
RUN apt-get update && apt-get install -y libelf1 libc6 && rm -rf /var/lib/apt/lists/*

# Copy the Go binary and the eBPF object from the builder.
COPY --from=builder /workspace/opensnoop /opensnoop
COPY --from=builder /workspace/opensnoop.o /opensnoop.o

ENTRYPOINT ["/opensnoop"]

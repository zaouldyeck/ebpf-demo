#############################
# Stage 1: Build Kernel Headers
#############################
FROM debian:buster-slim AS kernel-headers

RUN apt-get update && apt-get install -y wget xz-utils make gcc bc rsync

WORKDIR /usr/src
RUN wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.5.tar.xz && \
    tar -xf linux-6.12.5.tar.xz && \
    rm linux-6.12.5.tar.xz

WORKDIR /usr/src/linux-6.12.5
RUN make mrproper
RUN make headers_install INSTALL_HDR_PATH=/usr/src/linux-headers

#############################
# Stage 2: Build eBPF Object and Go Binary
#############################
FROM golang:1.23 AS builder

WORKDIR /workspace

RUN apt-get update && apt-get install -y clang-16 llvm-16 libelf-dev libc6-dev build-essential

COPY --from=kernel-headers /usr/src/linux-headers /usr/src/linux-headers
ENV C_INCLUDE_PATH=/usr/src/linux-headers

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN clang-16 -O2 -g -Wall -target bpf -nostdinc -D__TARGET_ARCH_arm64 \
    -isystem `clang-16 -print-resource-dir`/include \
    -isystem /usr/src/linux-headers/include \
    -isystem /usr/src/linux-headers/include/uapi \
    -I. \
    -c opensnoop.c -o opensnoop.o

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o opensnoop .

#############################
# Stage 3: Create the Runtime Image
#############################
FROM debian:buster

RUN apt-get update && apt-get install -y libelf1 libc6 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/opensnoop /opensnoop
COPY --from=builder /workspace/opensnoop.o /opensnoop.o

ENTRYPOINT ["/opensnoop"]

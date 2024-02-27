FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git wget \
    virtualenvwrapper python3-dev python3-pip python-is-python3 python3-venv \
    clang-15 lld-15 \
    qemu-user \
    libc6-armhf-cross libc6-arm64-cross \
    libc6-mips-cross libc6-mips64-cross \
    libc6-powerpc-cross libc6-powerpc-ppc64-cross \
    libc6-mipsel-cross libc6-mips64el-cross \
    libc6-ppc64el-cross \
    && rm -rf /var/lib/apt/lists/*

COPY . /patcherex2
WORKDIR /patcherex2

RUN pip install -U pip pytest ruff
RUN pip install -e /patcherex2

CMD ["/bin/bash"]

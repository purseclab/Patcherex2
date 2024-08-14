FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git wget unzip \
    virtualenvwrapper python3-dev python3-pip python-is-python3 python3-venv \
    openjdk-17-jdk \
    clang-15 lld-15 \
    qemu-user \
    gcc-multilib \
    libc6-armhf-cross libc6-arm64-cross \
    libc6-mips-cross libc6-mips64-cross \
    libc6-powerpc-cross libc6-powerpc-ppc64-cross \
    libc6-mipsel-cross libc6-mips64el-cross \
    libc6-ppc64el-cross \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
    && echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-19 main" | tee /etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y clang-19 lld-19 \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip \
    && unzip /ghidra_11.0.3_PUBLIC_20240410.zip

ENV GHIDRA_INSTALL_DIR=/ghidra_11.0.3_PUBLIC

COPY . /patcherex2

RUN pip install -U pip pytest ruff
RUN pip install -e /patcherex2[all]

CMD ["/bin/bash"]

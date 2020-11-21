FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y eatmydata apt-utils
RUN eatmydata apt-get install -y --no-install-recommends \
    wget ca-certificates \
    perl make \
    gcc-mingw-w64 g++-mingw-w64 \
    cmake ninja-build

RUN useradd -m builder
USER builder
WORKDIR /home/builder

RUN wget https://www.openssl.org/source/openssl-1.1.1h.tar.gz && tar xzvf openssl-1.1.1h.tar.gz
RUN cd openssl-1.1.1h && ./Configure --prefix=$HOME/dist --cross-compile-prefix=x86_64-w64-mingw32- no-idea no-mdc2 no-rc5 shared mingw64
RUN cd openssl-1.1.1h && make -j5 && make install && make clean

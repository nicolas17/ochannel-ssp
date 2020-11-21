FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y eatmydata apt-utils
RUN eatmydata apt-get install -y --no-install-recommends \
    libssl-dev \
    gcc g++ \
    cmake ninja-build

RUN useradd -m builder
USER builder
WORKDIR /home/builder

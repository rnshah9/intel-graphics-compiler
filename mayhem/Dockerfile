FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential

COPY . /repo
WORKDIR /repo/IGC/BiFModule/linux
RUN g++ -o linux_resource_linker linux_resource_linker.cpp

FROM ubuntu:22.04 as package
COPY --from=builder /repo/IGC/BiFModule/linux/linux_resource_linker /

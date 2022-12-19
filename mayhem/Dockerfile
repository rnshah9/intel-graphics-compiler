FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang

COPY . /repo
WORKDIR /repo/IGC/BiFModule/linux
RUN g++ -o linux_resource_linker linux_resource_linker.cpp
RUN clang++ /repo/mayhem/fuzz_sprintf_s.cpp -fsanitize=fuzzer,address -I /repo/inc/common/ -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/IGC/BiFModule/linux/linux_resource_linker /
COPY --from=builder /fuzz /fuzz_sprintf_s

# Build and run with:
#
# docker build -t pq-bench . && docker run -it --privileged -v $(pwd)/kex/data:/pq-bench/kex/data pq-bench
#
# This will run the server in your current shell. Open another shell and run the experiment with:
#
# docker exec $(docker ps --filter ancestor=pq-bench -q) python3 experiment.py

FROM public.ecr.aws/ubuntu/ubuntu:22.04_stable

RUN mkdir /pq-bench
COPY . /pq-bench
WORKDIR /pq-bench

# If running this outside of Docker, run the below apt commands in your ubuntu
# VM's shell before running install-prereqs-ubuntu.sh
RUN apt update -y
RUN apt install -y \
               git \
               autoconf \
               automake \
               build-essential \
               cmake=3.22.1-1ubuntu1.22.04.1 \
               curl \
               golang-go \
               iproute2=5.15.0-1ubuntu2 \
               iputils-ping \
               libtool \
               libpcre3-dev \
               ninja-build=1.10.1-1 \
               openssl=3.0.2-0ubuntu1.10 \
               python3=3.10.6-1~22.04 \
               sudo

RUN ./install-prereqs-ubuntu.sh
WORKDIR /pq-bench/kex
RUN make s_timer.o

CMD ./setup.sh

# Build and run with:
#
# $ docker build -t accp -f Dockerfile.dev .
# $ docker run -v $(pwd):/accp --rm -it accp:latest
#
# Once in the container's shell, quickly iterate on rebuilding AWS-LC and ACCP
# to re-run a single test with:
#
# $ SINGLE_TEST=com.amazon.corretto.crypto.provider.test.EvpSignatureTest
# $ ./gradlew minimal_clean && ./gradlew single_test -DSINGLE_TEST=${SINGLE_TEST}

FROM public.ecr.aws/ubuntu/ubuntu:22.04_stable

RUN mkdir /pq-bench
COPY . /pq-bench
WORKDIR /pq-bench

RUN ./install-prereqs-ubuntu.sh
WORKDIR /pq-bench/kex

ENTRYPOINT ./setup.sh && python3 experiment.py

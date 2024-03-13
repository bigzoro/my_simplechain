# Build Sipe in a stock Go builder container
FROM golang:1.16-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers
ENV GOPROXY=https://goproxy.cn
ADD . /go-simplechain
RUN cd /go-simplechain && make sipe

# Pull Sipe into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /go-simplechain/build/bin/sipe /usr/local/bin/
WORKDIR /app
ADD ./shell/sipe.sh ./
#EXPOSE 8545 8546 30312 30312/udp
CMD ["sipe"]
#docker build -t simplechain/sipe:release-1.0 .

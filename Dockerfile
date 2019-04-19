FROM alpine:3.8
RUN apk add --update ca-certificates
COPY dist/linux-amd64/presto-proxy /presto-proxy
ENTRYPOINT ["/presto-proxy"]

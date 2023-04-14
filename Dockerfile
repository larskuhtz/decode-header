FROM alpine:latest as build
LABEL maintainer="Lars Kuhtz <lakuhtz@gmail.com>"
WORKDIR /app
COPY decode-header.c .
RUN apk --no-cache add gcc musl-dev
RUN gcc -static -o decode-header decode-header.c

FROM scratch
COPY --from=build /app/decode-header /decode-header
ENTRYPOINT ["/decode-header"]

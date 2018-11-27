FROM tozny/golang

RUN mkdir -p /go/src/github.com/tozny/e3db-go/

COPY . /go/src/github.com/tozny/e3db-go/
WORKDIR /go/src/github.com/tozny/e3db-go/

RUN CGO_ENABLED=0 go build && \
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/e3db && \
  mv e3db /bin/

ENTRYPOINT ["e3db"]

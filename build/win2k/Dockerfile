FROM golang:1.23 AS builder

COPY . /repo

WORKDIR /repo

RUN make generate-win
RUN mv build/win/artifactcollector32.syso artifactcollector.syso

FROM golang:1.2.2-cross

ENV GOPATH=/gopath
ENV GOOS=windows
ENV GOARCH=386
ENV CGO_ENABLED=1
ENV CC=gcc

COPY --from=builder /repo /repo

RUN mkdir -p /gopath
RUN mv /repo/vendor /gopath/src

COPY ./build/go/context/context.go /gopath/src/context/context.go
COPY ./build/go/fs /gopath/src/io/fs

RUN mv /repo /gopath/src/github.com/forensicanalysis/artifactcollector
RUN cp -r /gopath/src/github.com/forensicanalysis/artifactcollector/build/go /gopath/src

WORKDIR /gopath/src/github.com/forensicanalysis/artifactcollector

ENV CC=i686-w64-mingw32-gcc

CMD ["go", "build", "-o", "/build/artifactcollector2k.exe", "."]

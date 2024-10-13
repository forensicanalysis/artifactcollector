FROM golang:1.17 AS builder

COPY . /repo

WORKDIR /repo

RUN go install golang.org/x/tools/cmd/goimports@v0.1.7
RUN go install github.com/forensicanalysis/go-resources/cmd/resources@v0.4.0
RUN go install github.com/akavel/rsrc@v0.10.2
RUN go run tools/yaml2go/main.go pack/ac.yaml pack/artifacts/*
RUN resources -package assets -output assets/bin.generated.go pack/bin/*
RUN rsrc -arch amd64 -manifest build/win/artifactcollector.exe.manifest -ico build/win/artifactcollector.ico -o build/win/artifactcollector.syso
RUN rsrc -arch 386 -manifest build/win/artifactcollector32.exe.manifest -ico build/win/artifactcollector.ico -o build/win/artifactcollector32.syso
RUN rsrc -arch amd64 -manifest build/win/artifactcollector.exe.user.manifest -ico build/win/artifactcollector.ico -o build/win/artifactcollector.user.syso
RUN rsrc -arch 386 -manifest build/win/artifactcollector32.exe.user.manifest -ico build/win/artifactcollector.ico -o build/win/artifactcollector32.user.syso
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

COPY --from=builder /usr/local/go/src/io/fs /gopath/src/io/fs
COPY --from=builder /usr/local/go/src/internal/oserror /gopath/src/internal/oserror

RUN mv /repo /gopath/src/github.com/forensicanalysis/artifactcollector
RUN cp -r /gopath/src/github.com/forensicanalysis/artifactcollector/build/go /gopath/src

RUN sed -i 's#sort\.Slice(list, func(i, j int) bool { return list\[i]\.Name() < list\[j]\.Name() })#sort.Sort(SortedDir(list))#g' /gopath/src/io/fs/readdir.go
RUN echo "type SortedDir []DirEntry" >> /gopath/src/io/fs/readdir.go
RUN echo "func (a SortedDir) Len() int           { return len(a) }" >> /gopath/src/io/fs/readdir.go
RUN echo "func (a SortedDir) Less(i, j int) bool { return a[i].Name() < a[j].Name() }" >> /gopath/src/io/fs/readdir.go
RUN echo "func (a SortedDir) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }" >> /gopath/src/io/fs/readdir.go

RUN echo "package afero" > /gopath/src/github.com/spf13/afero/memmap.go

WORKDIR /gopath/src/github.com/forensicanalysis/artifactcollector

ENV CC=i686-w64-mingw32-gcc

CMD ["go", "build", "-o", "/build/artifactcollector2k.exe", "."]

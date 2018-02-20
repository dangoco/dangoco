# dangoco
(団子子)
A proxy over websocket

*node.js^7.5.0 is required. [Don't have?](https://github.com/dangoco/dangoco/wiki/FAQ#how-can-i-use-it-if-i-dont-have-the-required-version-of-nodejs)*

## Using

```shell
npm i -g dangoco
```

## Client

```shell
dangocoClient [options]

#see --help for options

#example
dangocoClient -s ws://example.com/xxx -u dango -p test --socksHost 0.0.0.0 --socksPort 1080  -a aes-256-cfb
# --socksHost 0.0.0.0			start a client listening on 0.0.0.0:1080 for socks connections 
# --socksPort 1080
# -s ws://example.com/xxx		and use ws://example.com/xxx as the proxy server
# -u dango -p test				the username is dango and the password is test
# -a aes-256-cfb				using an encryption algorithm aes-256-cfb cause it is an insecure connection
#								wss(websocket over https) is recommended,or the inspector may recognize your proxy(including url and websocket tunnel control frames)
```


## Server

```shell
dangocoServer [options]

#see --help for options

#example
dangocoServer -u '[["dango","test"]]' -L
# -u '[["dango","test"]]'	set a json with users in it
# -L						display logs(for debug)
# the server listens on 127.0.0.1:80 by default.You can set -h host -p port to specify it.
```

## Supported protocol

* TCP
* UDP
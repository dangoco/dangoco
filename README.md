# dangoco
(団子子)
A proxy over websocket

## using

```shell
npm i dangoco -g
```

## client

```shell
dangocoClient [options]

#see --help for options

#example
dangocoClient -s ws://example.com/xxx -u dango -p test -S 0.0.0.0:1080  -a aes-256-cfb --ignore-error
# -S 0.0.0.0:1080				start a client listening on 0.0.0.0:1080 for socks5 connections 
# -s ws://example.com/xxx 		and use ws://example.com/xxx as the proxy server
# -u dango -p test 				the username is dango and the password is test
# -a aes-256-cfb 				using an encryption algorithm aes-256-cfb cause it is an insecure connection
# 								wss(websocket over https) is recommended,or the inspector may recognize your proxy(including url and websocket tunnel control frames)
# --ignore-error 				prevent it from stoping when error occurs
```


## server

```shell
dangocoServer [options]

#see --help for options

#example
dangocoServer --ignore-error -u '[["dango","test"]]' -L
# -u '[["dango","test"]]' 	set a json with users in it
# -L 						display logs(for debug)
# the server listens on 127.0.0.1:80 by default.You can set -h host -p port to specify it.

```

# UDP not works for now
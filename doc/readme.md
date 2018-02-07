# Instruction

## dangoco structure

dangoco client <==> a web stream <==> dangoco server

In this version, the web stream indicates a websocket stream.

## Connecting

The client connects to the server with a websocket address, which looks like this: 
```
ws://dangoco.etc/the/optional/path/username?encryptedParamName=encryptedParamValue&ibid
```

The encrypted parts is encrypted uses aes-256-cfb,the password is user password.

The server will try decrypting the parameters uses user password.

Any condition except successfully decrypting the parameters will not return a success response to client.

*editing*
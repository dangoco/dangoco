/*
dangoco-node.js server class

Copyright 2017 dangoco
*/
'use strict';

const net=require('net'),
	os=require('os'),
	IP=require('ip'),
	events=require('events'),
	crypto=require('crypto'),
	dgram = require('dgram'),
	socks5=require('socks5Server'),
	dangocoUDPTools=require('./udp.js'),
	// ipAddress=require('ip-address'),
	{URLSearchParams} = require('url'),
	{proxyAgent}=require('./proxyAgent.js'),
	tunnelServer=require('ws-stream-tunnel').server,
	{urlSafeBase64,md5,aes256cfb,de_aes256cfb,authString} = require('./verifyTools.js');

const ciphers=new Set(crypto.getCiphers());
/*
user verify
	client:
		ws(s)://proxyAddr/?u=user&s=authCode
			authCode:
				md5(aes256cfb(authString,password))
	server:
		verifyClient(user,authCode)
			md5(aes256cfb(authString,password))
				compare	with authCode

encryption:
	i think it's useless in wss connections. It may just be used in ws connections
	add 'c=cAlgorithm' in requset url
	cAlgorithm:
		urlSafeBase64(aes256cfb(algorithm,password))

*/

/*
opt:
	the same with https://github.com/websockets/ws/blob/master/doc/ws.md#new-websocketserveroptions-callback
*/
class dangocoServer extends events{
	constructor(opt,callback){
		super();
		let options=Object.assign({},opt);
		this.userVerfyClient=options.verifyClient||verifyClient;
		options.verifyClient=(info,cb)=>{
			this.userVerfyClient(info,(result,code,name)=>{
				if(result!==true){
					cb(result,code,name);
					return;
				}
				this.parseWsRequest(info,cb);
			});
		};
		this.options=options;
		this._tunnelServer=new tunnelServer(options,callback);

		//default users map
		this.users=new Map(); //user=>pass

		//store proxy
		this.proxy=new WeakMap(); //stream=>ProxyStream
		this.userProxy=new Map(); //user=>Set(ProxyStream)

		//default block logic
		this.blockRules=new Set();
		this.BLOCKEDADDR=new Set(['localhost',os.hostname(),
								'0.0.0.0','255.255.255.255',
								'::','FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF']);
		this.blockRules.add((type,addr)=>{//rule:block addr
			if(this.BLOCKEDADDR.has(addr))return true;
			else if(type<=4){//ip
				if(IP.isPrivate(addr))return true;
			}
		});

		this._tunnelServer.on('tunnel',tunnel=>{
			tunnel.on('stream_open',stream=>{
				let ws=this._tunnelServer.getWsOfTunnel(tunnel);
				let req=this._tunnelServer.getReqOfWs(ws);
				new ProxyStream(this,stream,req._algo,req._user,req._key);
			});
		});

		//set user's proxystream in userProxy
		this.on('proxy_open',proxystream=>{
			let user=proxystream.user,
				set=this.userProxy.get(user);

			if(!set)this.userProxy.set(user,set=new Set());
			set.add(proxystream);
			this.proxy.set(proxystream.stream,proxystream)
		}).on('proxy_close',proxystream=>{
			let user=proxystream.user,
				set=this.userProxy.get(user);
			if(!set)return;
			set.delete(proxystream);
			if(set.size===0)
				this.userProxy.delete(user);
			this.proxy.delete(proxystream.stream);
		});

	}
	parseWsRequest(info,cb){
		try{
			var req=info.req,
				querys=new URLSearchParams(info.req.url.replace(/^.+\?/,'')),
				user=querys.get('u'),
				authCode=querys.get('s'),
				cAlgorithm=querys.get('c'),
				wd=querys.get('wd');
		}catch(e){
			cb(false,500,'server error');
		}
		this.getPass(user,(pass)=>{
			if(pass===false){
				this.emit('verify_failed',{
					user,
					msg:'no password of the user found'
				});
				cb(false,200);
				return;
			}
			//auth user
			let auth=md5(aes256cfb(authString,pass));
			if(auth===authCode){
				req._user=user;
				req._pass=pass;
			}else{
				this.emit('verify_failed',{
					user,
					msg:`wrong password:${pass}`
				});
				cb(false,200);
				return;
			}

			//encrypt
			if(cAlgorithm){
				let algo=de_aes256cfb(urlSafeBase64.decode(cAlgorithm),pass).toString('utf8').trim();
				if(!ciphers.has(algo)){
					this.emit('verify_failed',{
						user,
						msg:`not supported algorithm:${algo}`
					});
					cb(false,500,'not supported algorithm');
					return;
				}
				if(!wd){//if no key(wd) provided
					cb(false,400,'key not set');
					return;
				}
				wd=de_aes256cfb(urlSafeBase64.decode(wd),pass);
				info.req._algo=algo;
				info.req._key=wd;
			}
			cb(true);
		});

	}
	getPass(user,cb){//default get pass method,can be overwritten
		let pass=this.users.get(user);
		if(typeof pass !== 'string'){
			pass=false;//means error
		}
		setImmediate(cb,pass);
	}
	close(){
		this._tunnelServer.close();
	}
	isBlockedAddr(addr){
		let type;
		if(net.isIPv4(addr))type=2;
		else if(net.isIPv6(addr))type=3;
		else{type=9;}
		for(let r of this.blockRules){
			if(r(type,addr)===true)return true;
		}
	}
}
function verifyClient(info,cb){
	setImmediate(cb,true);
}

/*
streaming data:
	client request:(decrypted)
		stream[0 ~ 1]:proxy head length
		stream[2 ~ stream[0]]:proxy head(json)
		stream[the rest]:raw stream
	server:(decrypted)
		stream[all]:stream from target server(tcp)

TCP:
	client head:
		_: 		'proxy'
		type: 	'tcp'
		addr: 	target address
		port: 	target port


UDP:
	client head:
		_: 			'proxy'
		type: 		'udp'
		udpMode:	'relay'||'stream'
		addr: 		client addr (for 'relay')
		port: 		client port (for 'relay')

	UDP over stream: udp frame in stream
		udp frame:
			uses socks5 udp head(but the leading 2 bytes is the size of the frame,the 3rd byte is 0xFF),following data

	UDP relay:
		client:listen on a port and send the proxy request to server.
		server:listen on a port and reply the client.(the listening port receives udp data from dangoco client and target server)(the host is which the client connected to)
		client:encrypt handled message if algo specified,send to server
		server:decrypt the message if needed,send it to target server
	
*/

/*
events:
	proxy_open:(ProxyStream)
	proxy_close:(ProxyStream)
*/
class ProxyStream extends events{
	constructor(server,stream,algo,user,key){
		super();
		this.server=server;

		this.user=user;
		this.key=key;
		
		this.head=[];
		this.headLength=0;
		this.headParsed=false;
		this._headBytesCount=0;
		this._dataListener=this._dataListener.bind(this);

		this.opened=false;//will be marked as true when proxy head all received
		this.closed=false;

		this.agent=new proxyAgent(stream,algo,key);

		this._timer=setTimeout(()=>{
			stream.destroy('time out');
		},15000);

		stream.once('tunnel_stream_close',()=>this._close());
		this.inStream.on('data',this._dataListener);
	}
	get stream(){return this.agent.stream;}
	get inStream(){return this.agent.inStream;}
	get outStream(){return this.agent.outStream;}
	_dataListener(chunk){
		if(this.headParsed){
			return;
		}else if(this.headLength){
			this._buildHead(chunk);
		}else{
			this.headLength=(chunk[0]<<8)+chunk[1];//this byte is not counted in headLength
			if(this.headLength===0){
				this.stream.destroy('invalid head length');
				return;
			}
			if(chunk.byteLength>1){
				this._buildHead(chunk.subarray(2));
			}
		}
	}
	_buildHead(chunk){
		if(this.headLength===0){
			if(this.headLength===0){
				this.stream.destroy('invalid head length');
				return;
			}
		}
		if(chunk.byteLength<(this.headLength-this._headBytesCount+1)){
			this.head.push(chunk);
			this._headBytesCount+=chunk.byteLength;
		}else{
			let left=this.headLength-this._headBytesCount;
			this.head.push(chunk.subarray(0,left));
			this._headBytesCount+=left;
			this.inStream.unshift(chunk.subarray(left));
		}
		if(this.headLength===this._headBytesCount){
			try{
				this.head=JSON.parse(Buffer.concat(this.head));
			}catch(e){
				this.stream.destroy(e);
				return;
			}
			this.headParsed=true;
			this._eat();
		}
	}
	_eat(){
		clearTimeout(this._timer);
		switch(this.head._){
			case 'proxy':{
				this._proxy();
				return;
			}
			default:{
				this.stream.destroy('invalid request: '+this.head._);
				return;;
			}
		}
	}
	_proxy(){
		if(!this.headParsed){
			this.stream.destroy('proxy_error: head not parsed');
			return;
		}
		let head=this.head;
		switch(head.type){
			case 'tcp':{
				this._tcpProxy();
				break;
			}
			case 'udp':{
				this._udpProxy();
				break;
			}
			default:{
				this.stream.destroy('proxy_error: not supported proxy type: '+head.type);
				return;
			}
		}
	}
	_proxyEvent(stream){
		this.inStream.removeListener('data',this._dataListener);
		stream.once('error',e=>{
			this.server.emit('proxy_error',this,e);
		});
		this.opened=true;
		this.server.emit('proxy_open',this);
	}
	_tcpProxy(){
		this._proxyEvent(this.stream);
		const head=this.head;
		if(!head.port || !head.addr){
			this.stream.destroy('destination wrong');
			return;
		}
		if(this.server.isBlockedAddr(head.addr)){
			this.stream.destroy('blocked address');
			return;
		}
		this.inStream.pause();
		let socket=net.createConnection({port:head.port, host:head.addr});
		this.stream.once('end',()=>{if(socket.connecting)socket.destroy()});
		socket.once('connect',()=>{
			this.inStream.pipe(socket);
			socket.pipe(this.outStream);
		}).on('error',e=>{
			this.stream&&this.stream.destroy('connection_error: '+e.message);
		});
	}
	_udpProxy(){
		this._proxyEvent(this.stream);
		if(this.head.udpMode==='relay'){//listen on a udp port and forward it
			this._udpModeRelay();
		}else if(this.head.udpMode==='stream'){//pack udp msgs and delivery in stream
			this._udpModeStream();
		}else{
			this.stream.destroy('invalid udpMode');
			return;
		}
	}
	_udpModeRelay(){
		this.relaySocket=dgram.createSocket('udp4');

		this.usedClientAddress;
		this.usedClientPort;
	}
	_udpModeStream(){
		this.relaySocket=dgram.createSocket('udp4');
		this.dangocoUDP=new dangocoUDPTools.dangocoUDP();

		//close the udp socket if the stream ended
		this.stream.once('end',()=>this.relaySocket.close());

		this.dangocoUDP.on('frame',(frame,headLength)=>{
			this.relaySocket.send(
				frame.slice(headLength),//data
				socks5.Port.read(frame,3),//port
				socks5.Address.read(frame,3),//address
				err=>{
					console.debug('udp error',err);
				});
		}).once('error',err=>{
			this.stream.destroy('wrong data for udp frame');
			return;
		});

		this.relaySocket.on('message',(msg,info)=>{
			this.outStream.write(dangocoUDPTools.dangocoUDP.build(info.address,info.port,msg));
		});

		this.inStream.on('data',chunk=>{
			this.dangocoUDP.eat(chunk);//parse frames
		});
	}
	_close(){
		if(this.closed)return;
		if(this.opened)setImmediate(()=>this.server.emit('proxy_close',this));
		this.inStream.removeListener('data',this._dataListener);
		this.closed=true;
		this.opened=false;
	}
}

module.exports={
	dangocoServer,
}

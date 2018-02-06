/*
dangoco-node.js server class

Copyright 2017 dangoco
*/
'use strict';

const net=require('net'),
	os=require('os'),
	IP=require('ip'),
	pump=require('pump'),
	events=require('events'),
	crypto=require('crypto'),
	dgram = require('dgram'),
	socks5=require('socks5server'),
	dangocoUDPTools=require('./udp.js'),
	{URL,URLSearchParams} = require('url'),
	{proxyAgent}=require('./proxyAgent.js'),
	tunnelServer=require('ws-stream-tunnel').server,
	{urlSafeBase64,md5,aes256cfb,de_aes256cfb,authString} = require('./verifyTools.js');

const ciphers=new Set(crypto.getCiphers());
/*
user verify
	client:
		ws://proxyAddr/user?s=authCode
			params
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
		this.accessRuleSet=new accessRuleSet();
		this.tunnelServer=new tunnelServer(options,callback);

		//default users map
		this.users=new Map(); //user=>pass

		//store proxy
		this.proxy=new WeakMap(); //stream=>ProxyStream
		this.userProxy=new Map(); //user=>Set(ProxyStream)


		this.tunnelServer.on('tunnel_open',tunnel=>{
			tunnel.on('stream_open',stream=>{
				let ws=this.tunnelServer.getWsOfTunnel(tunnel),
					req=this.tunnelServer.getReqOfWs(ws);
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
				url=info.req.url.match(/^(.+?)\?(.+)$/),
				path=url[1],
				querys=new URLSearchParams(url[2]),
				user=path.match(/\/(.+)$/)[1];
		}catch(e){
			cb(false,500,'server error');
			return;
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
			//decode params
			let params={};
			for(let [n,v] of querys.entries()){
				params[de_aes256cfb(urlSafeBase64.decode(n),pass).toString('utf8')]=v;
			}
			//auth user
			let auth=md5(aes256cfb(pass,pass));
			if(auth===params.s){
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
			if(params.c){
				let algo=de_aes256cfb(urlSafeBase64.decode(params.c),pass).toString('utf8').trim();
				if(!ciphers.has(algo)){
					this.emit('verify_failed',{
						user,
						msg:`not supported algorithm:${algo}`
					});
					cb(false,500,'not supported algorithm');
					return;
				}
				if(!params.wd){//if no key(wd) provided
					cb(false,400,'key not set');
					return;
				}
				params.wd=de_aes256cfb(urlSafeBase64.decode(params.wd),pass);
				info.req._algo=algo;
				info.req._key=params.wd;
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
		this.tunnelServer.close();
	}
}
function verifyClient(info,cb){
	setImmediate(cb,true);
}


class accessRuleSet{
	constructor(){
		this.rules=new Map();

		
		//default block rule
		this.BLOCKEDADDR=new Set(['localhost',os.hostname(),
								'0.0.0.0','255.255.255.255',
								'::','FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF']);
		this.rules.set(Symbol('blocked-address'),(type,addr)=>{//rule:blocked address
			if(this.BLOCKEDADDR.has(addr))return true;
		});
		this.rules.set(Symbol('private-address'),(type,addr)=>{//rule:private address
			if(type<=4){//ip
				if(IP.isPrivate(addr))return true;
			}
		});
	}
	isBlocked(addr,port){//return true if blocked
		let addrType=9;
		if(net.isIPv4(addr))addrType=2;
		else if(net.isIPv6(addr))addrType=3;
		for(let [name,rule] of this.rules){
			if(rule(addrType,addr,port)===true)return true;
		}
	}
	static setTypeConst(){
		let types={
			TYPEDOMAIN:9,
			TYPEIPV4:2,
			TYPEIPV4:3,
		};
		for(let t in types)accessRuleSet[t]=types[t];
	}
}
accessRuleSet.setTypeConst();
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
		this._headBuilder=this._headBuilder.bind(this);

		this.opened=false;//will be marked as true when proxy head all received
		this.closed=false;

		this.agent=new proxyAgent(stream,algo,key);

		this._timer=setTimeout(()=>{
			stream.destroy('time out');
		},15000);

		stream.once('tunnel_stream_close',()=>this._close());
		this.inStream.on('data',this._headBuilder);
	}
	get stream(){return this.agent.stream;}
	get inStream(){return this.agent.inStream;}
	get outStream(){return this.agent.outStream;}
	_headBuilder(chunk){
		if(this.headLength){
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
		if(this.headParsed)return;
		if(this.headLength===0){
			this.stream.destroy('invalid head length');
			return;
		}
		let left=this.headLength-this._headBytesCount;
		if(chunk.byteLength<=left){
			chunk.byteLength&&this.head.push(chunk);
			this._headBytesCount+=chunk.byteLength;
		}else{
			this.head.push(chunk.subarray(0,left));
			this._headBytesCount+=left;
			this.inStream._readableState.sync=true;
			(chunk.byteLength-left>0)&&this.inStream.unshift(chunk.subarray(left));
		}
		if(this.headLength===this._headBytesCount){
			this.inStream.pause();
			this._parseHead();
			return;
		}
	}
	_parseHead(){
		try{
			this.head=JSON.parse(Buffer.concat(this.head));
		}catch(e){
			this.stream.destroy(e);
			return;
		}
		this.inStream.removeListener('data',this._headBuilder);
		this.headParsed=true;
		this._eat();
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
		if(this.server.accessRuleSet.isBlocked(head.addr,head.port)){
			this.stream.destroy('blocked address');
			return;
		}
		let socket=net.createConnection({port:head.port, host:head.addr});
		this.stream.once('end',()=>{if(socket.connecting)socket.destroy()});
		socket.once('connect',()=>{
			pump(this.inStream,socket);
			pump(socket,this.outStream);
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
		//no plan
	}
	_udpModeStream(){
		this.relaySocket=dgram.createSocket('udp4');
		this.dangocoUDP=new dangocoUDPTools.dangocoUDP();

		//close the udp socket if the stream ended
		this.stream.once('end',()=>this.relaySocket.close());

		this.dangocoUDP.on('frame',(frame,headLength)=>{
			let addr=socks5.Address.read(frame,3),
				port=socks5.Port.read(frame,3);
			if(this.server.accessRuleSet.isBlocked(addr,port)){
				return;
			}
			this.relaySocket.send(
				frame.slice(headLength),//data
				port,//port
				addr,//address
				err=>{
					err&&console.debug('udp error',err);
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
		this.inStream.removeListener('data',this._headBuilder);
		this.closed=true;
		this.opened=false;
	}
}

module.exports={
	dangocoServer,
}

/*
dangoco-node.js client class

Copyright 2017 dangoco
*/
'use strict';

const net=require('net'),
	pump=require('pump'),
	{URL}=require('url'),
	events=require('events'),
	crypto=require('crypto'),
	dangocoUDPTools=require('./udp.js'),
	{proxyAgent}=require('./proxyAgent.js'),
	tunnelClient=require('ws-stream-tunnel').client,
	{urlSafeBase64,md5,aes256cfb,authString} = require('./verifyTools.js');


const algorithms=new Set(crypto.getCiphers());
/*
options
	`ws-stream-tunnel`.tunnelClient's options:
	here is the original doc: https://github.com/JiaJiaJiang/ws-stream-tunnel#class--tunnelclientoptions
		mode : tunnel type.
		addr : target ws address
		ws : options object for ws connection
		idleTimeout : millisecond before closing the connection,0 presents always keep the connection,defaults to 15

settings:
	user:the user name for the dangoco proxy
	pass:the password for the user
	algo:the algorithm to use,leave it undefined or null for none encryption
	keyLength:the byteLength for generating a random key

One dangocoClient has one ws connection. One or more dangocoClient can be 
created in the dangocoProxyClient to connect to different proxy servers or 
to connect for different targets or programmes.

You can't pass more than one connections without a mixed stream tunnel,such as the 'subStream' tunnel.
*/

/*
events:
	tunnelClient events:
		tunnel_open:(tunnel)
		tunnel_close:(tunnel)
*/

class dangocoClient extends tunnelClient{
	constructor(options,settings){
		options=Object.assign({},options);
		settings=Object.assign({},settings);
		if(!settings)
			throw(new Error('there should be a \'settings\' object as the second arg.'));
		if(typeof settings.user !== 'string' || typeof settings.pass !== 'string')
			throw(new Error('wrong username or password'));
		if(settings.algo && !algorithms.has(settings.algo))
			throw(new Error('not supported algorithm'));
		if(settings.keyLength>128)
			throw(new Error('keyLength should not greater than 128'));

		super(options);//tunnelClient constroctor
		this.settings=Object.assign({},settings);
		this._reqConnections=new Set();
		this.proxyList=new Set();

		this.once('idle',()=>{
			this.close();
		}).on('beforeConnect',cb=>{
			cb(dangocoClient.generateAddr(options,this.settings));
		}).on('tunnel_open',()=>{
			for(let [clientStream,info] of this._waitingProxy){
				clientStream._waitingProxy=false;
				this._waitingProxy.delete(clientStream);
				this.proxy(info.protocol,info.addr,info.port,clientStream,info.callback);
			}
		});

		

		this.connectionMng.on('_wserror',(ws,err)=>{
			if(err.message.match(/ENOTFOUND|ECONNRESET/)){
				//close the client if these error emits
				this.close();
			}
		});

		this._waitingProxy=new Map();//store requests that waits for tunnel open

		this.connect();
	}
	proxy(protocol,addr,port,clientStream,callback){
		clientStream.isPaused()||clientStream.pause();//pause the stream,otherwise the data will escape

		let preSize=this._reqConnections.size;
		this._reqConnections.add(clientStream);
		if(this._reqConnections.size!==preSize)
		clientStream.once('end',()=>{
			if(clientStream._waitingProxy){
				this._waitingProxy.delete(clientStream);
			}
			this._reqConnections.delete(clientStream);
			if(this._reqConnections.size===0 && !(this.connectionMng.connecting || this.connectionMng.connected)){
				this.close();
			}
		});

		if(!this.tunnelCreated){
			clientStream._waitingProxy=true;
			this._waitingProxy.set(clientStream,{
				protocol,
				addr,
				port,
				callback,
			});
			return;
		}


		if(protocol==='tcp')this._TCPProxy(addr,port,clientStream,callback);
		else if(protocol==='udp')this._UDPProxy(addr,port,clientStream,callback);
		else throw(new Error('not supported protocol'));
	}
	_TCPProxy(addr,port,clientStream,callback){
		try{
			var tunnelStream=this._requestProxy({
				_:'proxy',
				type:'tcp',
				addr,
				port,
			});
		}catch(e){
			setImmediate(callback,Error('tunnel stream error'));
			return;
		}
		let piped=false;
		tunnelStream.once('tunnel_stream_open',()=>{
			pump(clientStream,tunnelStream.agent.outStream);
			pump(tunnelStream.agent.inStream,clientStream);
			piped=true;
			callback(null,tunnelStream);
		}).once('error',e=>{//destroy the client stream if an error occurred before tunnel stream opened
			if(!piped){
				callback(Error('tunnel stream error'));
			}
		});
		return tunnelStream;
	}

	_UDPProxy(clientAddress,clientPort,clientStream,callback){
/*
head:
	_: 			'proxy'
	type: 		'udp'
	udpMode:	'relay'||'stream'
	addr: 		client addr (for 'relay')
	port: 		client port (for 'relay')
*/
		let head={
			_:'proxy',
			type:'udp',
			udpMode:this.settings.udpInTunnel?'stream':'relay',
		};
		try{
			var tunnelStream=this._requestProxy(head);
		}catch(e){
			setImmediate(callback,Error('tunnel stream error'));
			return;
		}

		let udpDeliver=new dangocoUDPTools.udpDeliver();
		if(head.udpMode==='relay'){
			this._UDPRelay(clientAddress,clientPort,clientStream,udpDeliver);
		}else{
			this._UDPStream(udpDeliver,clientStream,tunnelStream);
		}
		tunnelStream.once('tunnel_stream_open',()=>{
			callback&&callback(null,udpDeliver);
			callback=null;
			udpDeliver.emit('ready');
		}).once('error',e=>{
			callback&&callback(Error('tunnel stream error'));
			callback=null;
		});
		// return udpDeliver;
	}
	_UDPRelay(){}
	_UDPStream(udpDeliver,clientStream,tunnelStream){
		udpDeliver.on('clientMsg',frame=>{
			tunnelStream.agent.outStream.write(frame);
		});

		clientStream.once('end',()=>{
			tunnelStream.agent.outStream.end();
		});
		tunnelStream.once('end',()=>{
			clientStream.end();
		});

		let dangocoUDP=new dangocoUDPTools.dangocoUDP();
		dangocoUDP.on('frame',frame=>{
			udpDeliver.emit('remoteMsg',frame);
		}).once('error',err=>{
			clientStream.destroy(err);
		});
		tunnelStream.agent.inStream.on('data',chunk=>{
			dangocoUDP.eat(chunk);
		});
	}
	_requestProxy(head){
		let headBuffer=Buffer.from(JSON.stringify(head));

		if(headBuffer.byteLength>65535)//too long head
			throw Error('too long head');

		let tunnelStream=this.tunnel.createStream();//create a stream
		let agent=new proxyAgent(tunnelStream,this.settings.algo,this.settings.key);
		head.tunnelStream=tunnelStream;
		tunnelStream.agent=agent;
		tunnelStream.once('tunnel_stream_open',()=>{//connect the streams when the tunnelStream opens
			agent.outStream.write(Buffer.from([headBuffer.byteLength>>>8,headBuffer.byteLength&0xFF]));//send head length
			agent.outStream.write(headBuffer);//send head

			this.proxyList.add(head);
			this.emit('proxy_open',head);
		}).once('tunnel_stream_close',()=>{
			this.proxyList.delete(head);
			this.emit('proxy_close',head);
		}).once('error',e=>{
			this.emit('proxy_error',head,e);
		});
		return tunnelStream;
	}
	close(msg){
		for(let [clientStream,info] of this._waitingProxy){
			clientStream.destroy(Error(msg));
		}
		this._waitingProxy.clear();
		super.close();
	}

	static generateAddr(options,settings){
		//combine args
		let url=new URL(options.addr),query=url.searchParams;
		url.pathname+=(url.pathname.endsWith('/')?'':'/')+settings.user;
		let time=Date.now(),
			tbl=Math.ceil(time.toString(16).length/2),
			tb=Buffer.allocUnsafe(tbl);
		tb.writeIntBE(time,0,tbl);

		query.set(urlSafeBase64.encode(aes256cfb('s',settings.pass)),urlSafeBase64.encode(aes256cfb(tb,settings.pass)));
		if(settings.algo){
			settings.key=crypto.randomBytes(settings.keyLength);//generate a key
			query.set(urlSafeBase64.encode(aes256cfb('c',settings.pass)),urlSafeBase64.encode(aes256cfb(settings.algo,settings.pass)));
			query.set(urlSafeBase64.encode(aes256cfb('wd',settings.pass)),urlSafeBase64.encode(aes256cfb(settings.key,settings.pass)));
		}
		return url.toString();
	}
}


exports.dangocoClient=dangocoClient;
/*
dangoco-node.js client class

Copyright 2017 dangoco
*/
'use strict';

const net=require('net'),
	events=require('events'),
	{URL,URLSearchParams}=require('url'),
	{proxyAgent}=require('./proxyAgent.js'),
	tunnelClient=require('ws-stream-tunnel').client,
	{urlSafeBase64,md5,aes256cfb,authString} = require('./verifyTools.js');


const algorithms=new Set(require('crypto').getCiphers());
/*
options
	`ws-stream-tunnel`.tunnelClient's options:
	here is the original doc: https://github.com/JiaJiaJiang/ws-stream-tunnel#class--tunnelclientoptions
		mode : tunnel type.
		retry : max retry limit
		addr : target ws address
		ws : options object for ws connection
		idleTimeout : millisecond before closing the connection,0 presents always keep the connection,defaults to 0

settings:
	user:the user name for the dangoco proxy
	pass:the password for the user
	algo:the algorithm to use,leave it undefined or null for none encryption

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

		//combine args
		let url=new URL(options.addr),query=url.searchParams;
		query.set('u',settings.user);
		query.set('s',md5(aes256cfb(authString,settings.pass)));
		if(settings.algo)
			query.set('c',urlSafeBase64.encode(aes256cfb(settings.algo,settings.pass)));
		options.addr=url.toString();

		super(options);//tunnelClient constroctor
		this.settings=Object.assign({},settings);
		this.proxyList=new Set();
	}
	proxy(protocol,addr,port,stream){
		stream.pause();//pause the stream,otherwise the data will escape
		if(!this.multiProxy && this._proxyCount>=1)
			throw(new Error('multiProxy not supported in this client'));
		this._proxyCount++;

		if(!this.tunnelCreated)
			throw(new Error('tunnel not ready'));

		if(protocol==='tcp')return this._TCPProxy(addr,port,stream);
		else if(protocol==='udp')return this._UDPProxy(addr,port,stream);
		else throw(new Error('not supported protocol'));
	}
	_TCPProxy(addr,port,clientStream){
		let head={
			_:'proxy',
			type:'tcp',
			addr,
			port,
		},headBuffer=Buffer.from(JSON.stringify(head));

		if(headBuffer.byteLength>255){//too long head
			clientStream.destroy(new Error('too long head'));
			return;
		}

		let agent,tunnelStream=this.tunnel.createStream();//create a stream
		tunnelStream.once('tunnel_stream_open',()=>{//connect the streams when the tunnelStream opens
			
			agent=new proxyAgent(tunnelStream,this.settings.algo,this.settings.pass);
			agent.outStream.write(Buffer.from([headBuffer.byteLength]));//send head length
			agent.outStream.write(headBuffer);//send head

			clientStream.pipe(agent.outStream);
			agent.inStream.pipe(clientStream);

			this.proxyList.add(head);
			this.emit('proxy_open',head);

		}).once('tunnel_stream_close',()=>{
			this.proxyList.delete(head);
			this.emit('proxy_close',head);
		}).once('error',e=>{
			this.emit('proxy_error',head,e);
		});
	}
	_UDPProxy(addr,port,stream){}
}


exports.dangocoClient=dangocoClient;
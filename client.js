#!/usr/bin/env node
/*
dangoco-node.js client

Copyright 2017 dangoco
*/
'use strict';

const commander = require('commander');
	
commander
	.usage('[options]')
	//server options
	.option('-s, --server [value]', 'server address. example: ws://127.0.0.1:80')
	.option('-S, --socks [value]', 'listen on the address for socks proxy. example: 127.0.0.1:1080')

	//user options
	.option('-u, --user [value]', 'username')
	.option('-p, --pass [value]', 'password')

	//connections options
	.option('-a, --algo [value]', 'encryption algorithm,defaults to undefined. This should only be set in the insecurity connection')
	.option('--algolist', 'list all available algorithms')
	.option('-I, --idle <n>', 'idleTimeout,the connection will be automatically close after this idle time')
	.option('--ignore-error', 'keep running when having uncaught exception')
	.option('--disable-deflate', 'disable websocket deflate')
	.option('--keepBrokenTunnel', 'not close the tunnel when connection lost.(for bad network conditions)')
	.option('--connectionPerRequest', 'create a connection for every request')
	.option('--connectionPerTarget', 'create a connection for every target')
	.option('--connectionPerTCP', 'create a connection for every tcp request')
	.option('--connectionPerUDP', 'create a connection for every udp request')
	.option('--connectionForUDP', 'create a connection for all udp request')
	.parse(process.argv);

//--algolist
if(commander.algolist){//list all available algorithms
	console.log(require('crypto').getCiphers().join('\n'));
	return;
}

if(commander.ignoreError){
	process.on('uncaughtException',function(e){//prevent server from stoping when uncaughtException
	    console.error(e);
	});
}

//create a dangoco server
const {dangocoClient}=require('./lib/client.js'),
	socks5Server=require('socks5server'),
	net=require('net');

//options check
if(commander.idle && !(commander.idle>=0))
	throw(new Error('Invalid idleTimeout'));
if(typeof commander.user !== 'string' || commander.user.length===0)
	throw(new Error('Wrong username'));

const dangocoConfig={
	server:commander.server,
	user:commander.user,
	pass:commander.pass,
	algo:commander.algo,
	idle:commander.idle,
},
proxyConfig={
	connectionPerRequest:commander.connectionPerRequest||false,
	connectionPerTarget:commander.connectionPerTarget||false,
	connectionPerTCP:commander.connectionPerTCP||false,
	connectionPerUDP:commander.connectionPerUDP||false,
	connectionForUDP:commander.connectionForUDP||false,
};



/*
options:
	//connections rules (order by priority)
	connectionPerRequest : new connection for every new request
	connectionPerTCP : new connection for each TCP request
	connectionPerUDP : new connection for each UDP request(UDP in separate connections)
	connectionPerTarget : new connection for every different target(port included)
	connectionForUDP : new connection for UDP requests(UDP in one connection)

client names
	default 		(for requests not in the rule)
	X:random 		(for perRequest rule)
	Target:target 	(for perTarget rule)
	TCP:random 		(for perTCP rule)
	UDP:random 		(for perUDP rule)
	UDP 			(for UDP fule)
*/

class dangocoProxyClient{
	constructor(dangocoConfig,proxyConfig){
		this.dangocoConfig=Object.assign({},dangocoConfig);
		this.proxyConfig=Object.assign({},proxyConfig);
		this.clients=new Map();
	}
	proxy(protocol,addr,port,stream,callback){
		let [clientName,tunnelMode]=this._getClientInfo(protocol,addr,port),
			client=this.clients.get(clientName);

		if(!client){//create a new client if not exists
			console.log('[new client]',clientName);
			client=new dangocoClient({
				mode:tunnelMode,
				addr:this.dangocoConfig.server,
				ws:{
					perMessageDeflate:!commander.disableDeflate,
				},
				idleTimeout:this.dangocoConfig.idle||5*60000,//defaults to 5 minutes
			},{
				user:this.dangocoConfig.user,
				pass:this.dangocoConfig.pass,
				algo:this.dangocoConfig.algo,
			});
			client.clientName=clientName;
			client.once('close',()=>{
				this.clients.delete(client.clientName);//remove from client list
				console.log('[close client]',clientName);
			}).on('error',e=>{
				console.error('[tunnel error]',e)
			}).on('proxy_open',info=>{
				console.log('[proxy]',`(${info.type})`,`${info.addr}:${info.port}`);
			}).on('proxy_close',info=>{
				if(tunnelMode!=='subStream'){
					client.close();
					this.clients.delete(clientName);
				}
				console.log('[proxy close]',`(${info.type})`,`${info.addr}:${info.port}`);
			}).on('proxy_error',(info,e)=>{
				console.error('[proxy error]',`(${info.type})`,`${info.addr}:${info.port}`,(e instanceof Error)?e.message:e)
			});

			client.connectionMng.on('_wserror',(ws,err)=>{
				console.error('connection error:',err.message)
			});

			this.clients.set(clientName,client);
		}
		if(!client.tunnelCreated){
			client.once('tunnel_open',()=>{
				callback();
				client.proxy(protocol,addr,port,stream);
			});
		}else{
			callback();
			client.proxy(protocol,addr,port,stream);
		}
	}
	_randomName(){//generate a random name value
		return Math.round(Math.random()*544790277504495).toString(32)+'_'+Date.now().toString(32);
	}
	_getClientInfo(protocol,addr,port){//generate the client name
		let name='default',multiConnection=true;
		if(this.proxyConfig.connectionPerRequest){
			name=`X:${this._randomName()}`;
			multiConnection=false;
		}else if(this.proxyConfig.connectionPerTCP && protocol==='tcp'){
			name=`TCP:${this._randomName()}`;
			multiConnection=false;
		}else if(this.proxyConfig.connectionPerUDP && protocol==='udp'){
			name=`UDP:${this._randomName()}`;
			multiConnection=false;
		}else if(this.proxyConfig.connectionPerTarget){
			name=`Target:${addr}@${port}`;
		}else if(this.proxyConfig.connectionForUDP){
			name=`UDP`;
		}
		if(!multiConnection && this.clients.has(name))
			return this._getClientInfo(protocol,addr,port);
		return [name,multiConnection?'subStream':'stream'];//use stream mode for private tunnel,subStream mode for mixed tunnel
	}
}

const proxyClient=new dangocoProxyClient(dangocoConfig,proxyConfig);




//the socks サーバ
if(typeof commander.socks==='string'){
	let ap=commander.socks.split(/\:/g);
	if(ap.length!==2)
		throw(new Error(`Invalid socks server address: ${commander.socks}`));
	initSocksServer(ap[0],ap[1]);
}

function initSocksServer(addr,port){
	var s5server=socks5Server.createServer();

	s5server.on('tcp',(socket, port, address, CMD_REPLY)=>{
		proxyClient.proxy('tcp',address,port,socket,()=>{
			CMD_REPLY();
		});
	}).on('error', function (e) {
		console.error('SERVER ERROR: %j', e);
		if(e.code == 'EADDRINUSE') {
			console.log('Address in use, retrying in 10 seconds...');
			setTimeout(function () {
				console.log('Reconnecting to %s:%s', HOST, PORT);
				s5server.close();
				s5server.listen(PORT, HOST);
			}, 10000);
		}
	}).on('client_error',(socket,e)=>{
		console.error('  [client error]',`${net.isIP(socket.targetAddress)?'':'('+socket.targetAddress+')'} ${socket.remoteAddress}:${socket.targetPort}`,e.message);
	}).on('socks_error',(socket,e)=>{
		console.error('  [socks error]',`${net.isIP(socket.targetAddress)?'':'('+socket.targetAddress+')'} ${socket.remoteAddress}:${socket.targetPort}`,e.message);
	}).on('proxy_error',(proxy,e)=>{
		console.error('  [proxy error]',`${proxy.targetAddress}:${proxy.targetPort}`,e.message);
	}).listen(port, addr,()=>{
		console.log('socks server stared');
	});
}
#!/usr/bin/env node
/*
dangoco-node.js server


Copyright 2017 dangoco
*/
'use strict';

const commander = require('commander');
commander
	.usage('[options]')
	.option('-h, --host [value]', 'listen on the host for in coming proxy request. for example: 127.0.0.1')
	.option('-p, --port <n>', 'listen on the port for in coming proxy request. for example: 80')
	.option('-C, --control [value]', 'controller access code. this option wil enable the control api')
	.option('-L', 'display connection logs')
	.option('-u, --user [value]', 'user json. [["user","pass"],...]')
	.option('-v', 'display the version')
	.option('--user-file [value]', 'load a user json file.same format as ↑')
	.option('--algolist', 'list all available algorithms')
	.option('--ignore-error', 'keep running when having uncaught exception')
	.parse(process.argv);


//--algolist
if(commander.algolist){//list all available algorithms
	console.log(require('crypto').getCiphers().join('\n'));
	return;
}
//-v
if(commander.V){//display the version
	console.log(`dangoco version: ${require('./package.json').version}`);
	return;
}

const Log=commander.L;

const {dangocoServer} = require('./lib/server.js'),
	byteSize = require('byte-size');
const serverOptions={
	host:commander.host || '127.0.0.1',
	port:commander.port || 80,
	perMessageDeflate:true,
};

const server=new dangocoServer(serverOptions,(...args)=>{
	console.log('server started at',server._tunnelServer._server.address());
});

server.on('proxy_open',proxy=>{
	let set=server.userProxy.get(proxy.user);
	Log&&console.log(`[${proxy.head.type}]`,`[${proxy.user}](🔗 ${set?set.size:0})`,_targetString(proxy.head));
}).on('proxy_close',proxy=>{
	let set=server.userProxy.get(proxy.user);
	let inSize=byteSize(proxy.agent.in),
		outSize=byteSize(proxy.agent.out);
	Log&&console.log(`[${proxy.head.type}]`,`[${proxy.user}](🔗 ${set?set.size:0})`,`[↑${inSize.value}${inSize.unit},↓${outSize.value}${outSize.unit}]`,_targetString(proxy.head),'closed');
}).on('proxy_error',(proxy,e)=>{
	Log&&console.error(`[${proxy.head.type}]`,`[${proxy.user}]`,_targetString(proxy.head),(e instanceof Error)?e.message:e);
}).on('verify_failed',info=>{
	Log&&console.log('[verify failed]',`(${info.user})`,info.msg);
});

function _targetString(head){
	if(head.addr)return `${head.addr}:${head.port}`;
	return 'no target';
}

if(commander.ignoreError)
	process.on('uncaughtException',function(e){//prevent server from stoping when uncaughtException
	    console.error(e);
	});

/*user*/
{
	let userList=[];
	//--user-file
	if(commander.userFile){
		let path=require('path'),
			filePath=path.resolve(process.cwd(),commander.userFile),
			users=require(filePath);
		userList=userList.concat(users);
	}
	//-u
	if(commander.user){
		try{
			var userJson=JSON.parse(commander.user);
		}catch(e){
			console.error('user parsing error:',e);
		}
		userList=userList.concat(userJson);
	}
	//load
	for(let u of userList){
		if(typeof u[1]==='number')u[1]=String(u[1]);
		server.users.set(u[0],u[1]);
	}
}



/*control api*/


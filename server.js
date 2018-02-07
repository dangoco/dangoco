#!/usr/bin/env node
/*
dangoco-node.js server


Copyright 2017 dangoco
*/
'use strict';

const commander = require('commander');
commander
	.usage('[options]')
	.version(`dangoco version: ${require('./package.json').version}`)
	.option('-h, --host [value]', 'listen on the host for in coming proxy request. for example: 127.0.0.1')
	.option('-p, --port <n>', 'listen on the port for in coming proxy request. for example: 80',Number)
	.option('-C, --control [value]', 'controller access code. this option wil enable the control api')
	.option('-L', 'display connection logs')
	.option('-u, --user [value]', 'user json. [["user","pass"],...]',v=>{try{return JSON.parse(v);}catch(e){console.log('user json:',v);throw('user parsing error:',e);}})
	.option('--user-file [value]', 'load a user json file. Same format as ↑')
	.option('--algolist', 'list all available algorithms')
	.option('--disable-block <items>', 'disable specific block rules',v=>v.split(','))
	.parse(process.argv);


//--algolist
if(commander.algolist){//list all available algorithms
	console.log(require('crypto').getCiphers().join('\n'));
	return;
}

/*-------------start of the server---------------*/
const Log=commander.L;


process.on('uncaughtException',function(e){//prevent server from stoping when uncaughtException
	console.error('uncaughtException',e);
});

const {dangocoServer} = require('./lib/server.js'),
	byteSize = require('byte-size');
const serverOptions={
	host:commander.host || '127.0.0.1',
	port:commander.port || 80,
	perMessageDeflate:true,
};

const server=new dangocoServer(serverOptions,(...args)=>{
	console.log('server started at',server.tunnelServer._server.address());
	if(commander.disableBlock){//disable block rules
		if(typeof commander.disableBlock === 'string')commander.disableBlock=[commander.disableBlock];
		for(let [r,func] of server.accessRuleSet.rules){
			let name=String(r),match;
			if(commander.disableBlock.indexOf(name)>=0 
				|| ((match=name.match(/^Symbol\((.+)\)$/))&&commander.disableBlock.indexOf(match[1])>=0)){
				console.log('disable block rule :',name);
				server.accessRuleSet.rules.delete(r);
			}
		}
	}
	
	

});

server.on('proxy_open',proxy=>{
	let set=server.userProxy.get(proxy.user);
	Log&&console.log(`[${proxy.head.type}]`,`[${proxy.user}](<-> ${set?set.size:0})`,_targetString(proxy.head));
}).on('proxy_close',proxy=>{
	let set=server.userProxy.get(proxy.user);
	let inSize=byteSize(proxy.agent.in),
		outSize=byteSize(proxy.agent.out);
	Log&&console.log(`[${proxy.head.type}]`,`[${proxy.user}](<-> ${set?set.size:0})`,`[↑${inSize.value}${inSize.unit},↓${outSize.value}${outSize.unit}]`,_targetString(proxy.head),'closed');
}).on('proxy_error',(proxy,e)=>{
	Log&&console.error(`[${proxy.head.type}]`,`[${proxy.user}]`,'error',_targetString(proxy.head),(e instanceof Error)?e.message:e);
}).on('verify_failed',info=>{
	Log&&console.log('[verify failed]',`(${info.user})`,info.msg);
});

function _targetString(head){
	if(head.addr)return `${head.addr}:${head.port}`;
	return 'unknown target';
}


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
	if(commander.user)
		userList=userList.concat(commander.user);
	//load
	for(let u of userList){
		if(typeof u[1]==='number')u[1]=String(u[1]);
		server.users.set(u[0],u[1]);
	}
}



/*control api*/


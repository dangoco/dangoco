/*
Copyright 2017 dangoco
*/
'use strict';
const crypto=require('crypto');

const authString=Buffer.from('welcome to　Japari Park');//🐱🐧🐻🦉


var b64={
	encode:(buffer)=>{
		if(typeof buffer === 'string')buffer=Buffer.from(buffer);
		else if(!Buffer.isBuffer(buffer)){throw(new TypeError('not a buffer nor a string'))}
		return buffer.toString('base64').replace(/\+|\=|\//g,(c)=>{
			if(c==='+')return '-';
			else if(c==='/')return '_';
			else if(c==='=')return '.';
		});
	},
	decode:(bString)=>{
		if(typeof bString !== 'string')
			throw(new TypeError('not a base46 string'));
		return Buffer.from(bString.replace(/\-|\_|\./g,(c)=>{
			if(c==='-')return '+';
			else if(c==='_')return '/';
			else if(c==='.')return '=';
		}),'base64');
	}
}


function md5(data){
	let hash = crypto.createHash('md5');
	hash.update(data);
	return hash.digest('hex');
}

function aes256cfb(data,pass){
	let c=crypto.createCipher('aes-256-cfb',pass),en,f;
	en=[c.update(data)];
	f=c.final();
	if(f)en.push(f);
	return Buffer.concat(en);
}
function de_aes256cfb(data,pass){
	let c=crypto.createDecipher('aes-256-cfb',pass),de,f;
	de=[c.update(data)];
	f=c.final();
	if(f)de.push(f);
	return Buffer.concat(de);
}

module.exports={
	urlSafeBase64:b64,
	md5,
	aes256cfb,
	de_aes256cfb,
	authString,
}
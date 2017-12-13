/*
Copyright 2017 dangoco
*/
'use strict';
const crypto = require('crypto'),
	{PassThrough}=require('stream');

const passThroughOpt={allowHalfOpen:false};

class proxyAgent{
	constructor(stream,algo,pass){
		this.in=0;
		this.out=0;

		this.stream=stream;
		this.outStream=algo?crypto.createCipher(algo,pass):new PassThrough(passThroughOpt);
		this.inStream=algo?crypto.createDecipher(algo,pass):new PassThrough(passThroughOpt);
		this.outStream.pipe(stream);
		stream.pipe(this.inStream);

		this.outStream.on('data',buf=>this.out+=buf.byteLength);
		this.inStream.on('data',buf=>this.in+=buf.byteLength);
	}
	clear(){
		this.inStream=this.outStream=this.stream=null;
	}
}

exports.proxyAgent=proxyAgent;
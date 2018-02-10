/*
Copyright 2017 dangoco
*/
'use strict';
const pump=require('pump'),
	crypto = require('crypto'),
	{PassThrough,Duplex}=require('stream');

const passThroughOpt={allowHalfOpen:false};


class proxyAgent{
	constructor(stream,algo,pass){
		this.time=Date.now();
		this.in=0;
		this.out=0;

		this.stream=stream;

		this.outStream=algo?crypto.createCipher(algo,pass):new PassThrough(passThroughOpt);
		this.inStream=algo?crypto.createDecipher(algo,pass):new PassThrough(passThroughOpt);
		this.outStream.on('data',buf=>this.out+=buf.byteLength);
		this.inStream.on('data',buf=>this.in+=buf.byteLength);
		pump(this.outStream,stream);
		pump(stream,this.inStream);

	}
}

exports.proxyAgent=proxyAgent;
/*
Copyright 2017 dangoco
*/
'use strict';
const events=require('events'),
	socks5=require('socks5Server');

/*
events:
	frame: picked out dangoco udp frame
	error: cant parse the frame
*/
class dangocoUDP extends events{
	constructor(){
		super();
		this.pending=[];
		this._bytesLeft=0;//bytes left to combine a new frame
		this.error=false;
	}
	eat(chunk){//build frames
		if(this.error)return;
		if(this._bytesLeft>0){//slice bytes to the pending array
			// if(this._bytesLeft===chunk.byteLength)
			if(this._bytesLeft<=chunk.byteLength){
				let noLeft=this._bytesLeft===chunk.byteLength;
				this.pending.push(noLeft?chunk:chunk.slice(0,this._bytesLeft));
				this._frame(Buffer.concat(this.pending));
				this.pending.length=0;
				let newStart=this._bytesLeft;
				this._bytesLeft=0;
				if(!noLeft)
					this.eat(chunk.slice(newStart));
			}else{
				this.pending.push(chunk);
			}
			return;
		}
		//a new start
		if(chunk.byteLength<2){//cant get the length of the frame
			this.pending.push(chunk);
			return;
		}
		let length=(chunk[0]<<8)+chunk[1];
		if(chunk.byteLength<length){//the chunk carries the part of the frame
			this._bytesLeft=length-chunk.byteLength;
			this.pending.push(chunk);
		}else if(chunk.byteLength>length){//the chunk carries more than a frame
			this._frame(chunk.slice(0,length));
			this.eat(chunk.slice(length));
		}else{
			this._frame(chunk);
		}
	}
	_frame(chunk){//emit frames
		let headLength;
		if(headLength=dangocoUDP.hasValidUDPHead(chunk)){
			this.emit('frame',chunk,headLength);
			return;
		}
		this.error=true;
		this.emit('error',Error('wrong head'));
		return;
	}

	static build(addr,port,data){
		let arr=[socks5.replyHead5(addr,port)];
		if(data)arr.push(data);
		let frame=Buffer.concat(arr);//almost the same format with socks5 udp head
		dangocoUDP.socks5ToDangoco(frame);
		return frame;
	}
	static socks5ToDangoco(frame){
		//set frame length
		frame[0]=frame.byteLength>>>8;
		frame[1]=frame.byteLength&0xFF;
		//set 0xFF
		frame[2]=0xFF;
	}
	static hasValidUDPHead(chunk){//return false if it's not a valid head,otherwise return the head size
		if(chunk[2]!==0xFF){return false;}
		let minLength=6;//data length without addr
		if(chunk[3]===0x01){minLength+=4;}
		else if(chunk[3]===0x03){minLength+=chunk[4];}
		else if(chunk[3]===0x04){minLength+=16;}
		else return false;
		if(chunk.byteLength<minLength){return false;}
		return minLength;
	}
}

/*
events:
	clientMsg: (frame) 
		frame: built by dangocoUDP.build
	remoteMsg: (frame)
		frame: built by dangocoUDP.build
*/
class udpDeliver extends events{
	//just a cover
}

const udp={
	dangocoUDP,
	udpDeliver,
}

module.exports=udp;
/*
Copyright 2017 dangoco
*/
'use strict';


/*
control json
	_id:msg id (a json with a same id will be sent back as a callback)
	_type: null(it's a reply) false(error)  other(action name) 
	msg: object
*/
class IPCControl{
	constructor(proc){
		this.actions={};
		this.proc=null;

		this._requests=new Map();

		this._handle.bind(this);

		proc&&this.listen(proc);
	}
	listen(proc){
		proc.on('message',this._handle);
	}
	action(name,func){
		this.actions[name]=func;
		return this;
	}
	request(name,msg,callback){
		if(name===null)
			throw(TypeError('request name cannot be null'));
		let id=IPCControl.randomID();
		this._send(id,name,msg,err=>{
			if(err)return;
			callback&&this._requests.set(id,callback);
		});
	}
	_handle(msg){
		if(!IPCControl.isControlJson(msg))return;
		if(msg._type===null){//reply
			let cb=this._requests.get(msg._id);
			if(cb){
				this._requests.delete(msg._id)
				cb(...msg.msg);
			}
		}if(msg._type===false){//internal error
			throw Error(msg.msg);
		}else if(msg._ in this.actions){//request
			this.actions[msg._](msg,(...resp)=>{
				this._send(msg._id,null,resp);//reply
			});
		}else{//unknown action
			this._send(msg._id,false,'unknown action:'+msg._type);
		}
	}
	_send(id,type,msg,callback){
		let m={
			_id:id,
			_type:type,
			msg,
		}
		let m=Object.assign({},msg);
		m.id=_id;
		m._type=_type;
		m.msg=msg;
		this.proc.send(m,err=>{
			err&&console.debug('IPC sending error:',err);
			if(callback)callback(err||null);
		});
	}


	static randomID(){
		return `${Date.now().toString(32)}-${((Math.random()*0xFFFFFF)|0).toString(32)}`;
	}
	static isControlJson(msg){
		if(('_id' in msg)===false)return false;;
		if(msg._type===0){
			if(('_' in msg)===false)return false;
		}else if(msg._type!==1){
			return false;
		}
		return true;
	}
}

module.exports=IPCControl;
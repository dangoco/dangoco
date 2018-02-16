
var debug;
try{
	debug=require('debug')('dangoco');
}catch(e){
	debug=()=>{};
}

module.exports=debug;
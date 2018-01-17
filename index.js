/*
dangoco-node.js

Copyright 2017 dangoco
*/
'use strict';

const commander = require('commander');
commander
	.usage('-M [mode] [options]')
	.option('-M, --mode [value]', 'select the mode: server || client')
	.parse(process.argv);

switch(commander.mode){
	case 'server':{
		require('./server.js');
		break;
	}
	case 'client':case undefined:{
		require('./client.js');
		break;
	}
	default:
		throw('Unrecognized mode:'+commander.mode);
}

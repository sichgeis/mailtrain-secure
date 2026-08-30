'use strict';

const builtinFork = require('child_process').fork;

const cleanExit = () => process.exit();
process.on('SIGINT', cleanExit); // catch ctrl-c
process.on('SIGTERM', cleanExit); // catch kill

const children = [];
const forwardedEnvironmentVariables = ['NODE_CONFIG', 'NODE_CONFIG_DIR', 'NODE_ENV'];

process.on('message', msg => {
    if (msg === 'exit') {
        cleanExit();
    }
});


process.on('exit', function() {
    for (const child of children) {
        child.send('exit');
    }
});

function fork(path, args, opts) {
    const childOptions = {...opts, env: {...opts.env}};
    for (const variable of forwardedEnvironmentVariables) {
        if (childOptions.env[variable] === undefined && process.env[variable] !== undefined) {
            childOptions.env[variable] = process.env[variable];
        }
    }

    const child = builtinFork(path, args, childOptions);

    children.push(child);
    return child;
}

module.exports.fork = fork;
module.exports.forwardedEnvironmentVariables = forwardedEnvironmentVariables;

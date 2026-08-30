'use strict';

const fs = require('fs');
const http = require('http');
const net = require('net');
const mysql = require('/app/server/node_modules/mysql2/promise');
const {MongoClient} = require('/app/zone-mta/node_modules/mongodb');

const configuration = JSON.parse(fs.readFileSync('/run/mailtrain-config/production.json', 'utf8'));

async function checkMysql() {
    const connection = await mysql.createConnection({...configuration.mysql, connectTimeout: 3000});
    try {
        await connection.query('SELECT 1');
    } finally {
        await connection.end();
    }
}

function redisCommand(parts) {
    return `*${parts.length}\r\n${parts.map(part => `$${Buffer.byteLength(part)}\r\n${part}\r\n`).join('')}`;
}

function checkRedis() {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection({host: configuration.redis.host, port: configuration.redis.port});
        let response = '';
        const timer = setTimeout(() => socket.destroy(new Error('timeout')), 3000);
        socket.setEncoding('utf8');
        socket.on('connect', () => socket.write(redisCommand(['AUTH', configuration.redis.password]) + redisCommand(['PING'])));
        socket.on('data', chunk => {
            response += chunk;
            if (response.includes('+OK\r\n') && response.includes('+PONG\r\n')) {
                clearTimeout(timer);
                socket.end();
                resolve();
            }
        });
        socket.on('error', error => {
            clearTimeout(timer);
            reject(error);
        });
        socket.on('close', () => {
            clearTimeout(timer);
            if (!response.includes('+PONG\r\n')) reject(new Error('unhealthy Redis response'));
        });
    });
}

function checkMongo() {
    return new Promise((resolve, reject) => {
        MongoClient.connect(configuration.builtinZoneMTA.mongo, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 3000
        }, async (error, client) => {
            if (error) return reject(error);
            try {
                await client.db('zone-mta').command({ping: 1});
                resolve();
            } catch (commandError) {
                reject(commandError);
            } finally {
                client.close();
            }
        });
    });
}

function checkHttp() {
    return new Promise((resolve, reject) => {
        const request = http.get({
            host: '127.0.0.1',
            port: 3000,
            path: '/',
            headers: {Host: process.env.MAILTRAIN_TRUSTED_HOST},
            timeout: 3000
        }, response => {
            response.resume();
            response.statusCode >= 200 && response.statusCode < 500 ? resolve() : reject(new Error('unhealthy HTTP response'));
        });
        request.on('timeout', () => request.destroy(new Error('timeout')));
        request.on('error', reject);
    });
}

(async () => {
    try {
        await Promise.all([checkMysql(), checkRedis(), checkMongo()]);
        await checkHttp();
    } catch (error) {
        process.stderr.write('Mailtrain dependency health check failed\n');
        process.exitCode = 1;
    }
})();

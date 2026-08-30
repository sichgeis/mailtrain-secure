'use strict';

const dns = require('dns').promises;
const http = require('http');
const https = require('https');
const net = require('net');
const config = require('./config');

const blockedIpv4 = new net.BlockList();
for (const [network, prefix] of [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
    ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
    ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
]) {
    blockedIpv4.addSubnet(network, prefix, 'ipv4');
}

const globalIpv6 = new net.BlockList();
globalIpv6.addSubnet('2000::', 3, 'ipv6');
const blockedIpv6 = new net.BlockList();
for (const [network, prefix] of [
    ['2001:10::', 28], ['2001:20::', 28], ['2001:db8::', 32], ['2002::', 16]
]) {
    blockedIpv6.addSubnet(network, prefix, 'ipv6');
}

function outboundError(message, code = 'EOUTBOUND') {
    const error = new Error(message);
    error.code = code;
    return error;
}

function isPublicAddress(address) {
    const family = net.isIP(address);
    if (family === 4) {
        return !blockedIpv4.check(address, 'ipv4');
    }
    if (family === 6) {
        return globalIpv6.check(address, 'ipv6') && !blockedIpv6.check(address, 'ipv6') && !blockedIpv4.check(address, 'ipv6');
    }
    return false;
}

function normalizePolicy(policy) {
    return {
        allowedPorts: Array.from(policy.allowedPorts || [80, 443]).map(Number),
        maxRedirects: Number(policy.maxRedirects),
        timeoutMs: Number(policy.timeoutMs),
        maxResponseSize: Number(policy.maxResponseSize),
        allowedSubscriberDataOrigins: Array.from(policy.allowedSubscriberDataOrigins || []).map(origin => new URL(origin).origin)
    };
}

function validatePolicy(policy) {
    if (!Number.isInteger(policy.maxRedirects) || policy.maxRedirects < 0 ||
        !Number.isFinite(policy.timeoutMs) || policy.timeoutMs <= 0 ||
        !Number.isInteger(policy.maxResponseSize) || policy.maxResponseSize <= 0 ||
        policy.allowedPorts.length === 0 || policy.allowedPorts.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) {
        throw outboundError('Outbound security policy is invalid', 'EOUTBOUNDCONFIG');
    }
}

function validateUrl(value, policy) {
    let url;
    try {
        url = new URL(value);
    } catch (err) {
        throw outboundError('Outbound URL is invalid');
    }
    if (!['http:', 'https:'].includes(url.protocol)) {
        throw outboundError('Outbound URL protocol is not allowed');
    }
    if (url.username || url.password || url.hash) {
        throw outboundError('Outbound URL credentials and fragments are not allowed');
    }
    const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
    if (!policy.allowedPorts.includes(port)) {
        throw outboundError('Outbound URL port is not allowed');
    }
    return url;
}

function encodeForm(form) {
    const encoded = new URLSearchParams();
    for (const [key, value] of Object.entries(form || {})) {
        for (const item of Array.isArray(value) ? value : [value]) {
            encoded.append(key, item === null || item === undefined ? '' : String(item));
        }
    }
    return Buffer.from(encoded.toString());
}

function nativeRequestOnce({url, address, family, method, headers, body, timeoutMs, maxResponseSize}) {
    return new Promise((resolve, reject) => {
        let settled = false;
        let responseEnded = false;
        let deadline;
        const transport = url.protocol === 'https:' ? https : http;
        const request = transport.request({
            protocol: url.protocol,
            hostname: url.hostname,
            port: url.port || undefined,
            method,
            path: `${url.pathname}${url.search}`,
            headers,
            agent: false,
            lookup: (hostname, options, callback) => {
                if (options && options.all) {
                    return callback(null, [{address, family}]);
                } else {
                    return callback(null, address, family);
                }
            }
        }, response => {
            const chunks = [];
            let length = 0;
            const fail = error => {
                if (settled) {
                    return;
                }
                settled = true;
                clearTimeout(deadline);
                request.destroy(error);
                reject(error);
            };
            response.on('data', chunk => {
                length += chunk.length;
                if (length > maxResponseSize) {
                    request.destroy(outboundError('Outbound response exceeded the size limit', 'EOUTBOUNDSIZE'));
                    return;
                }
                chunks.push(chunk);
            });
            response.once('aborted', () => fail(outboundError('Outbound response was aborted', 'ECONNRESET')));
            response.once('error', fail);
            response.once('close', () => {
                if (!responseEnded) {
                    fail(outboundError('Outbound response closed before completion', 'ECONNRESET'));
                }
            });
            response.once('end', () => {
                responseEnded = true;
                if (settled) {
                    return;
                }
                settled = true;
                clearTimeout(deadline);
                resolve({
                    statusCode: response.statusCode,
                    headers: response.headers,
                    body: Buffer.concat(chunks)
                });
            });
        });
        deadline = setTimeout(() => {
            if (settled) {
                return;
            }
            settled = true;
            const error = outboundError('Outbound request timed out', 'ETIMEDOUT');
            request.destroy(error);
            reject(error);
        }, timeoutMs);
        request.once('error', error => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(deadline);
            reject(error);
        });
        if (body && body.length > 0) {
            request.write(body);
        }
        request.end();
    });
}

async function withTimeout(promise, timeoutMs) {
    let timer;
    try {
        return await Promise.race([
            promise,
            new Promise((resolve, reject) => {
                timer = setTimeout(() => reject(outboundError('Outbound request timed out', 'ETIMEDOUT')), timeoutMs);
            })
        ]);
    } finally {
        clearTimeout(timer);
    }
}

function createOutboundFetcher(inputPolicy, {
    resolveHostname = hostname => dns.lookup(hostname, {all: true, verbatim: true}),
    requestOnce = nativeRequestOnce,
    isAddressAllowed = isPublicAddress,
    now = Date.now
} = {}) {
    const policy = normalizePolicy(inputPolicy);
    validatePolicy(policy);

    return async function outboundFetch(initialUrl, options = {}) {
        const maxRedirects = options.maxRedirects === undefined ? policy.maxRedirects : Math.min(policy.maxRedirects, Number(options.maxRedirects));
        const timeoutMs = options.timeoutMs === undefined ? policy.timeoutMs : Math.min(policy.timeoutMs, Number(options.timeoutMs));
        const maxResponseSize = options.maxResponseSize === undefined ? policy.maxResponseSize : Math.min(policy.maxResponseSize, Number(options.maxResponseSize));
        if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || !Number.isFinite(timeoutMs) || timeoutMs <= 0 ||
            !Number.isInteger(maxResponseSize) || maxResponseSize <= 0) {
            throw outboundError('Outbound request limits are invalid');
        }
        const startedAt = now();
        let url = validateUrl(initialUrl, policy);
        let method = String(options.method || 'GET').toUpperCase();
        let body = options.form ? encodeForm(options.form) : options.body ? Buffer.from(options.body) : null;
        let headers = {...(options.headers || {})};
        const sensitiveData = options.sensitiveData === true;
        let redirects = 0;

        if (options.form) {
            headers['content-type'] = 'application/x-www-form-urlencoded';
        }

        // Each redirect must repeat DNS validation before a new connection.
        // eslint-disable-next-line no-constant-condition
        while (true) {
            if (sensitiveData && body && url.protocol !== 'https:') {
                throw outboundError('Outbound subscriber data requires HTTPS');
            }
            if (sensitiveData && body && !policy.allowedSubscriberDataOrigins.includes(url.origin)) {
                throw outboundError('Outbound subscriber data destination is not explicitly approved');
            }

            const remaining = timeoutMs - (now() - startedAt);
            if (remaining <= 0) {
                throw outboundError('Outbound request timed out', 'ETIMEDOUT');
            }
            const hostname = url.hostname.startsWith('[') && url.hostname.endsWith(']') ?
                url.hostname.slice(1, -1) : url.hostname;
            const literalFamily = net.isIP(hostname);
            let addresses;
            if (literalFamily) {
                addresses = [{address: hostname, family: literalFamily}];
            } else {
                // eslint-disable-next-line no-await-in-loop
                addresses = await withTimeout(Promise.resolve(resolveHostname(hostname)), remaining);
            }
            if (!Array.isArray(addresses) || addresses.length === 0 || addresses.some(({address}) => !isAddressAllowed(address))) {
                throw outboundError('Outbound destination must resolve only to public addresses');
            }
            const selected = addresses[0];
            // eslint-disable-next-line no-await-in-loop
            const response = await withTimeout(requestOnce({
                url,
                address: selected.address,
                family: selected.family || net.isIP(selected.address),
                method,
                headers,
                body,
                timeoutMs: Math.max(1, timeoutMs - (now() - startedAt)),
                maxResponseSize
            }), Math.max(1, timeoutMs - (now() - startedAt)));
            if (!response || !Buffer.isBuffer(response.body)) {
                throw outboundError('Outbound transport returned an invalid response');
            }
            if (response.body.length > maxResponseSize) {
                throw outboundError('Outbound response exceeded the size limit', 'EOUTBOUNDSIZE');
            }

            const location = response.headers && response.headers.location;
            if (![301, 302, 303, 307, 308].includes(response.statusCode) || !location) {
                return {
                    statusCode: response.statusCode,
                    headers: response.headers || {},
                    body: response.body.toString(options.encoding || 'utf8'),
                    url: url.toString()
                };
            }
            if (redirects++ >= maxRedirects) {
                throw outboundError('Outbound redirect limit exceeded');
            }

            url = validateUrl(new URL(location, url).toString(), policy);
            if ([301, 302, 303].includes(response.statusCode) && method !== 'GET' && method !== 'HEAD') {
                method = 'GET';
                body = null;
                headers = {...headers};
                delete headers['content-type'];
                delete headers['content-length'];
            }
        }
    };
}

const defaultFetcher = createOutboundFetcher(config.security.outbound);

module.exports = {
    createOutboundFetcher,
    fetch: defaultFetcher,
    isPublicAddress
};

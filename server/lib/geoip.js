'use strict';

const geoip = require('geoip-lite');

function lookupCountry(address) {
    const result = geoip.lookup(address);
    return result && result.country || null;
}

module.exports = {lookupCountry};

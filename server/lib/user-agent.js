'use strict';

const {UAParser} = require('ua-parser-js');

function deviceType(userAgent) {
    const type = new UAParser(userAgent || '').getDevice().type;
    if (type === 'mobile') {
        return 'phone';
    }
    if (type === 'tablet') {
        return 'tablet';
    }
    return 'desktop';
}

module.exports = {deviceType};

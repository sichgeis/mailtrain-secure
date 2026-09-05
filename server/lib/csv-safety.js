'use strict';

function csvOptions(format) {
    if (format !== undefined && format !== 'safe' && format !== 'raw') {
        throw Object.assign(new Error('Unknown CSV format'), {status: 400});
    }
    if (format === 'raw') {return {};}
    // Control characters can conceal a spreadsheet formula prefix.
    // eslint-disable-next-line no-control-regex
    return {cast: {string: value => /^[\s\u0000-\u001f\u007f]*[=+@-]|^[\t\r\n\u0000]/u.test(value) ? '\'' + value : value}};
}

module.exports = {csvOptions};

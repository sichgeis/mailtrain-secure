'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {csvOptions} = require('../../lib/csv-safety');
const stringify = require('csv-stringify/lib/sync');

test('CSV neutralizes spreadsheet formulas including whitespace and control prefixes', () => {
    for (const value of ['=1+1', '+cmd', '-cmd', '@SUM(1)', '\t=1', '\r=1', '  =1', '\u0000=1']) {
        const output = stringify([[value]], csvOptions());
        assert.ok(output.includes("'"), JSON.stringify(value));
        assert.equal(stringify([[value]], csvOptions('raw')), stringify([[value]]));
    }
    assert.equal(stringify([['ordinary', 42]], csvOptions()), 'ordinary,42\n');
    assert.throws(() => csvOptions('invalid'));
});

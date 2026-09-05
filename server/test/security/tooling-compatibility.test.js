'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const toml = require('toml');
const flatted = require('flatted');
const Mocha = require('mocha');

test('patched TOML parser retains normal Mailtrain configuration values', () => {
    const parsed = toml.parse('[service]\nport = 3000\nenabled = true\nname = "Synthetic"\n');
    assert.equal(parsed.service.port, 3000);
    assert.equal(parsed.service.enabled, true);
    assert.equal(parsed.service.name, 'Synthetic');
});

test('patched lint cache parser retains circular-reference round trips', () => {
    const value = {name: 'synthetic'};
    value.self = value;
    const decoded = flatted.parse(flatted.stringify(value));
    assert.equal(decoded.self, decoded);
    assert.equal(decoded.name, 'synthetic');
});

test('supported Mocha runner retains its CommonJS suite API', async () => {
    const runner = new Mocha({reporter: function QuietReporter() {}});
    runner.suite.addTest(new Mocha.Test('synthetic compatibility check', () => assert.equal(2 + 2, 4)));
    assert.equal(await new Promise(resolve => runner.run(resolve)), 0);
});

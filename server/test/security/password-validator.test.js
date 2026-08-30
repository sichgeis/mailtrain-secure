'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const passwordValidator = require('../../../shared/password-validator');

test('password policy remains isolated and preserves translated validation errors', () => {
    const translated = passwordValidator((key, params) => `${key}:${params ? params.minLength : ''}`);
    const defaults = passwordValidator();

    assert.equal(translated.test('short').errors[0], 'thePasswordMustBeAtLeastMinLength:10');
    assert.match(defaults.test('short').errors[0], /at least 10 characters/);
    assert.equal(defaults.test('Correct-Horse-Battery-Staple').strong, true);
    assert.equal(defaults.test('AAAAaaaa1111!!!!').strong, false);
});

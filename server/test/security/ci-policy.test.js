'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const repositoryRoot = path.resolve(__dirname, '..', '..', '..');

test('CI exercises both supported database families without host production data', () => {
    const workflow = fs.readFileSync(path.join(repositoryRoot, '.github', 'workflows', 'security-ci.yml'), 'utf8');

    assert.match(workflow, /mariadb:10\.11/);
    assert.match(workflow, /mysql:8\.4/);
    assert.match(workflow, /redis:7/);
    assert.match(workflow, /ALLOW_DESTRUCTIVE_TESTS: YES_I_AM_USING_SYNTHETIC_DATA/);
    assert.doesNotMatch(workflow, /\/var\/lib\/mysql/);
});

test('CI preserves diagnostics and includes browser origin-isolation smoke tests', () => {
    const workflow = fs.readFileSync(path.join(repositoryRoot, '.github', 'workflows', 'security-ci.yml'), 'utf8');

    assert.match(workflow, /playwright/);
    assert.match(workflow, /if: failure\(\)/);
    assert.match(workflow, /actions\/upload-artifact@/);
    assert.match(workflow, /test:fast/);
});

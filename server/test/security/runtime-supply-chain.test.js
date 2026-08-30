'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const yaml = require('js-yaml');

const repositoryRoot = path.resolve(__dirname, '../../..');
const workspaces = ['server', 'client', 'shared', 'zone-mta'];

function read(relativePath) {
    return fs.readFileSync(path.join(repositoryRoot, relativePath), 'utf8');
}

function manifest(workspace) {
    return JSON.parse(read(`${workspace}/package.json`));
}

test('every shipped JavaScript workspace targets only Node 24 LTS', () => {
    assert.equal(read('.nvmrc').trim(), '24.20.0');
    for (const workspace of workspaces) {
        assert.equal(manifest(workspace).engines.node, '>=24.0.0 <25', workspace);
        assert.equal(manifest(workspace).packageManager, 'npm@11.19.0', workspace);
        assert.equal(JSON.parse(read(`${workspace}/package-lock.json`)).lockfileVersion, 3, workspace);
    }
    assert.match(read('.github/workflows/security-ci.yml'), /NODE_VERSION:\s*'24\.20\.0'/);
});

test('abandoned high-risk runtime packages are not production dependencies', () => {
    const forbidden = ['bcrypt-nodejs', 'crypto', 'geoip-ultralight', 'request', 'request-promise'];
    for (const workspace of workspaces) {
        const dependencies = manifest(workspace).dependencies || {};
        for (const packageName of forbidden) {
            assert.equal(dependencies[packageName], undefined, `${workspace} still ships ${packageName}`);
        }
    }
    assert.equal(manifest('shared').devDependencies['node-sass'], undefined);
});

test('lockfiles do not fetch dependencies from mutable VCS or local paths', () => {
    for (const workspace of workspaces) {
        const lockfile = read(`${workspace}/package-lock.json`);
        assert.doesNotMatch(lockfile, /"resolved":\s*"(?:git\+|github:|ssh:|file:)/, workspace);
    }
});

test('CI pins third-party actions and service images to immutable digests', () => {
    const workflowSource = read('.github/workflows/security-ci.yml');
    const workflow = yaml.safeLoad(workflowSource);
    for (const job of Object.values(workflow.jobs)) {
        for (const step of job.steps || []) {
            if (step.uses) {
                assert.match(step.uses, /^[^@]+@[0-9a-f]{40}$/);
            }
        }
        for (const service of Object.values(job.services || {})) {
            if (typeof service.image === 'string' && !service.image.includes('${{')) {
                assert.match(service.image, /@sha256:[0-9a-f]{64}$/);
            }
        }
    }
    assert.doesNotMatch(workflowSource, /uses:\s*[^\n]+@v\d/);
});

test('CI fails on high production advisories in every workspace', () => {
    const workflow = read('.github/workflows/security-ci.yml');
    for (const workspace of workspaces) {
        assert.match(workflow, new RegExp(`npm audit --omit=dev --audit-level=high --prefix ${workspace}`));
    }
    assert.doesNotMatch(workflow, /npm audit[^\n]*(?:\|\| true|continue-on-error)/);
});

test('CI emits an SBOM and scans the exact built image with a pinned scanner', () => {
    const workflow = read('.github/workflows/security-ci.yml');
    assert.match(workflow, /anchore\/sbom-action@[0-9a-f]{40}/);
    assert.match(workflow, /image:\s*mailtrain-security-ci:\$\{\{ github\.sha \}\}/);
    assert.match(workflow, /aquasecurity\/trivy-action@[0-9a-f]{40}/);
    assert.match(workflow, /image-ref:\s*mailtrain-security-ci:\$\{\{ github\.sha \}\}/);
    assert.match(workflow, /severity:\s*['"]?CRITICAL,HIGH/);
    assert.match(workflow, /exit-code:\s*['"]?1/);
    assert.match(workflow, /cyclonedx|spdx/i);
});

test('Docker build inputs and npm installs are reproducible', () => {
    const dockerfile = read('Dockerfile');
    assert.match(dockerfile, /^# syntax=docker\/dockerfile:[^@\n]+@sha256:[0-9a-f]{64}$/m);
    assert.doesNotMatch(dockerfile, /npm install(?:\s|$)/);
    assert.doesNotMatch(dockerfile, /^FROM (?![^\n]*@sha256:)/m);
    assert.equal(fs.existsSync(path.join(repositoryRoot, '.npmrc')), true);
    assert.match(read('.npmrc'), /audit=false/);
    assert.match(read('.npmrc'), /fund=false/);
});

test('Webpack provides an explicit browser process shim for Node-oriented editor dependencies', () => {
    assert.equal(manifest('client').dependencies.process, '0.11.10');
    assert.match(read('client/webpack.config.js'), /new webpack\.ProvidePlugin\(/);
    assert.match(read('client/webpack.config.js'), /process:\s*['"]process\/browser['"]/);
});

test('Webpack preserves default-object CSS module imports used by the legacy client', () => {
    const webpackConfig = read('client/webpack.config.js');
    assert.match(webpackConfig, /modules:\s*\{[\s\S]*?namedExport:\s*false/);
});

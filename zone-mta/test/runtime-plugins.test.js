'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {requiredRuntimePlugins, validateRuntimePlugins} = require('../lib/runtime-plugins');

test('the immutable runtime contains every required ZoneMTA plugin', () => {
    const zoneMtaDirectory = path.resolve(__dirname, '..');
    assert.doesNotThrow(() => validateRuntimePlugins(zoneMtaDirectory));

    assert.deepEqual(requiredRuntimePlugins, [
        'plugins/core/default-headers.js',
        'plugins/core/delivery-loop.js',
        'plugins/mailtrain-main.js',
        'plugins/mailtrain-receiver.js'
    ]);
});

test('runtime plugin validation fails closed for missing or malformed modules', t => {
    const zoneMtaDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'mailtrain-zonemta-plugins-'));
    t.after(() => fs.rmSync(zoneMtaDirectory, {recursive: true, force: true}));

    assert.throws(
        () => validateRuntimePlugins(zoneMtaDirectory),
        /required ZoneMTA plugin.*default-headers/i
    );

    for (const relativePath of requiredRuntimePlugins) {
        const pluginPath = path.join(zoneMtaDirectory, relativePath);
        fs.mkdirSync(path.dirname(pluginPath), {recursive: true});
        fs.writeFileSync(pluginPath, "'use strict'; module.exports = {};\n");
    }

    assert.throws(
        () => validateRuntimePlugins(zoneMtaDirectory),
        /required ZoneMTA plugin.*init/i
    );
});

test('vendored core plugins initialize the configured safety hooks', async () => {
    const defaultHeaders = require('../plugins/core/default-headers');
    const deliveryLoop = require('../plugins/core/delivery-loop');
    const defaultHeaderHooks = new Map();
    const deliveryLoopHooks = new Map();

    await defaultHeaders.init({
        config: {allowRoutingHeaders: []},
        addHook(name, handler) {
            defaultHeaderHooks.set(name, handler);
        }
    });
    await new Promise((resolve, reject) => {
        deliveryLoop.init({
            config: {maxHops: 35},
            addHook(name, handler) {
                deliveryLoopHooks.set(name, handler);
            }
        }, error => error ? reject(error) : resolve());
    });

    assert.equal(typeof defaultHeaderHooks.get('message:headers'), 'function');
    assert.equal(typeof deliveryLoopHooks.get('message:headers'), 'function');
});

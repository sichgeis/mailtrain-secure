'use strict';

const fs = require('node:fs');
const path = require('node:path');

const requiredRuntimePlugins = Object.freeze([
    'plugins/core/default-headers.js',
    'plugins/core/delivery-loop.js',
    'plugins/mailtrain-main.js',
    'plugins/mailtrain-receiver.js'
]);

function validateRuntimePlugins(zoneMtaDirectory = path.resolve(__dirname, '..')) {
    for (const relativePath of requiredRuntimePlugins) {
        const pluginPath = path.resolve(zoneMtaDirectory, relativePath);
        let stat;

        try {
            stat = fs.lstatSync(pluginPath);
        } catch (error) {
            throw new Error(`Required ZoneMTA plugin is missing: ${relativePath}`, {cause: error});
        }

        if (!stat.isFile()) {
            throw new Error(`Required ZoneMTA plugin is not a regular file: ${relativePath}`);
        }

        let plugin;
        try {
            plugin = require(pluginPath);
        } catch (error) {
            throw new Error(`Required ZoneMTA plugin could not be loaded: ${relativePath}`, {cause: error});
        }

        if (!plugin || typeof plugin.init !== 'function') {
            throw new Error(`Required ZoneMTA plugin does not export init(): ${relativePath}`);
        }
    }
}

module.exports = {requiredRuntimePlugins, validateRuntimePlugins};

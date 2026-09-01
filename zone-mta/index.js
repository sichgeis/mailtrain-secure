'use strict';

const path = require('node:path');
const {validateRuntimePlugins} = require('./lib/runtime-plugins');

// Some core plugins import ZoneMTA modules that initialize wild-config. Select
// the maintained package defaults before preflight so those imports cannot
// cache an incomplete application-only configuration.
process.env.NODE_CONFIG_DIR = path.join(path.dirname(require.resolve('@zone-eu/zone-mta')), 'config');

// wild-plugins logs and skips modules that cannot be loaded. Validate the
// immutable Mailtrain plugin set first so an incomplete image cannot accept or
// deliver mail with silently weakened processing.
validateRuntimePlugins(path.resolve(__dirname));

// start the app
require('@zone-eu/zone-mta');

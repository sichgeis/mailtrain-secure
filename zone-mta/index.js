'use strict';

const path = require('node:path');
const {validateRuntimePlugins} = require('./lib/runtime-plugins');

// wild-plugins logs and skips modules that cannot be loaded. Validate the
// immutable Mailtrain plugin set first so an incomplete image cannot accept or
// deliver mail with silently weakened processing.
validateRuntimePlugins(path.resolve(__dirname));

// start the app
require('@zone-eu/zone-mta');

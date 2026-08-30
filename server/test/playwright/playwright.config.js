'use strict';

const path = require('node:path');
const {defineConfig} = require('@playwright/test');

module.exports = defineConfig({
    testDir: __dirname,
    outputDir: path.join(__dirname, 'test-results'),
    retries: 1,
    reporter: [['line'], ['html', {outputFolder: path.join(__dirname, 'playwright-report'), open: 'never'}]],
    use: {
        trace: 'retain-on-failure'
    }
});

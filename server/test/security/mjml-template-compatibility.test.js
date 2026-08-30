'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const tools = require('../../lib/tools');

test('server-side MJML templates compile through the asynchronous maintained API', async () => {
    const renderer = await tools.getTemplate({
        template: 'subscription/web-subscribe.mjml.hbs',
        layout: 'subscription/layout.mjml.hbs',
        type: 'mjml'
    }, 'en-US');

    assert.equal(typeof renderer, 'function');
});

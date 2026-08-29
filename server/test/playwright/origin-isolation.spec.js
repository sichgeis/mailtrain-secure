'use strict';

const {expect, test} = require('@playwright/test');

const trustedOrigin = process.env.MAILTRAIN_TRUSTED_ORIGIN || 'http://127.0.0.1:3000';
const sandboxOrigin = process.env.MAILTRAIN_SANDBOX_ORIGIN || 'http://127.0.0.1:3003';
const publicOrigin = process.env.MAILTRAIN_PUBLIC_ORIGIN || 'http://127.0.0.1:3004';

test('trusted login is reachable only from the trusted origin', async ({request}) => {
    const trustedLogin = await request.get(`${trustedOrigin}/users/login`);
    expect(trustedLogin.status()).toBe(200);
    expect(await trustedLogin.text()).toContain('"appType":0');

    const untrustedResponses = await Promise.all([sandboxOrigin, publicOrigin].map(origin => request.get(`${origin}/users/login`)));
    for (const response of untrustedResponses) {
        expect(response.status()).toBe(404);
    }
});

test('public subscription content renders only from the public origin', async ({request}) => {
    const publicSubscription = await request.get(`${publicOrigin}/subscription/Hkj1vCoJb`);
    expect(publicSubscription.status()).toBe(200);
    expect(await publicSubscription.text()).toContain('<form');

    const trustedSubscription = await request.get(`${trustedOrigin}/subscription/Hkj1vCoJb`);
    expect(await trustedSubscription.text()).toContain('"appType":0');
});

test('synthetic admin can log in through the trusted origin', async ({page}) => {
    await page.goto(`${trustedOrigin}/users/login`);
    await page.locator('input[name="username"]').fill('admin');
    await page.locator('input[name="password"]').fill('test');
    await Promise.all([
        page.waitForURL(`${trustedOrigin}/`),
        page.locator('form[action="/login"] [type="submit"]').click()
    ]);
    await expect(page.locator('body')).toContainText('Logged in as admin');
});

'use strict';

const {expect, test} = require('@playwright/test');

const trustedOrigin = process.env.MAILTRAIN_TRUSTED_ORIGIN || 'http://127.0.0.1:3000';
const sandboxOrigin = process.env.MAILTRAIN_SANDBOX_ORIGIN || 'http://127.0.0.1:3003';
const publicOrigin = process.env.MAILTRAIN_PUBLIC_ORIGIN || 'http://127.0.0.1:3004';

test('trusted login is reachable only from the trusted origin', async ({request}) => {
    const trustedLogin = await request.get(`${trustedOrigin}/login`);
    expect(trustedLogin.status()).toBe(200);
    expect(await trustedLogin.text()).toContain('"appType":0');
    expect(trustedLogin.headers()['x-content-type-options']).toBe('nosniff');
    expect(trustedLogin.headers()['referrer-policy']).toBe('no-referrer');
    expect(trustedLogin.headers()['content-security-policy']).toContain('frame-ancestors \'none\'');

    const untrustedResponses = await Promise.all([sandboxOrigin, publicOrigin].map(origin => request.get(`${origin}/login`)));
    for (const response of untrustedResponses) {
        expect(response.status()).toBe(404);
    }
});

test('unsafe cross-origin requests fail before authentication handling', async ({request}) => {
    const response = await request.post(`${trustedOrigin}/rest/login`, {
        form: {username: 'admin', password: 'not-used'},
        headers: {Origin: 'https://attacker.example.test'}
    });
    expect(response.status()).toBe(403);
    expect(response.headers()['x-content-type-options']).toBe('nosniff');
});

test('sandbox and public origins receive role-specific framing policy', async ({request}) => {
    const sandboxResponse = await request.get(`${sandboxOrigin}/anonymous/codeeditor/editor`);
    expect(sandboxResponse.status()).toBe(200);
    expect(sandboxResponse.headers()['content-security-policy']).toContain('sandbox');
    expect(sandboxResponse.headers()['content-security-policy']).toContain(`frame-ancestors ${trustedOrigin}`);

    const publicResponse = await request.get(`${publicOrigin}/subscription/Hkj1vCoJb`);
    expect(publicResponse.status()).toBe(200);
    expect(publicResponse.headers()['content-security-policy']).toContain('frame-ancestors \'none\'');
    expect(publicResponse.headers()['x-frame-options']).toBe('DENY');
});

test('public subscription content renders only from the public origin', async ({request}) => {
    const publicSubscription = await request.get(`${publicOrigin}/subscription/Hkj1vCoJb`);
    expect(publicSubscription.status()).toBe(200);
    expect(await publicSubscription.text()).toContain('<form');

    const trustedSubscription = await request.get(`${trustedOrigin}/subscription/Hkj1vCoJb`);
    expect(await trustedSubscription.text()).toContain('"appType":0');
});

test('synthetic admin can log in through the trusted origin', async ({page}) => {
    await page.goto(`${trustedOrigin}/login`);
    await page.locator('#form_username').fill('admin');
    await page.locator('#form_password').fill('test');
    await Promise.all([
        page.waitForURL(`${trustedOrigin}/`),
        page.locator('button[type="submit"]').click()
    ]);
    await expect(page.locator('body')).toContainText('admin');
    const sessionCookie = (await page.context().cookies()).find(cookie => cookie.name === 'mailtrain.sid');
    expect(sessionCookie).toBeDefined();
    expect(sessionCookie.httpOnly).toBe(true);
    expect(sessionCookie.sameSite).toBe('Lax');
    expect(sessionCookie.expires).toBeGreaterThan(Date.now() / 1000);

    const reloginStatus = await page.evaluate(async () => {
        // eslint-disable-next-line no-undef
        const response = await globalThis.fetch('/rest/login', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                // eslint-disable-next-line no-undef
                'X-CSRF-TOKEN': globalThis.csrfToken
            },
            body: JSON.stringify({username: 'admin', password: 'test'})
        });
        return response.status;
    });
    expect(reloginStatus).toBe(200);
    const rotatedSessionCookie = (await page.context().cookies()).find(cookie => cookie.name === 'mailtrain.sid');
    expect(rotatedSessionCookie.value).not.toBe(sessionCookie.value);

    const csrfCookie = (await page.context().cookies()).find(cookie => cookie.name === '_csrf');
    expect(csrfCookie).toBeDefined();
    expect(csrfCookie.httpOnly).toBe(true);
    expect(csrfCookie.sameSite).toBe('Lax');
});

test('database-backed Mosaico editor initializes inside the sandbox origin', async ({page}) => {
    const dialogs = [];
    page.on('dialog', async dialog => {
        dialogs.push(dialog.message());
        await dialog.dismiss();
    });

    await page.goto(`${trustedOrigin}/login`);
    await page.locator('#form_username').fill('admin');
    await page.locator('#form_password').fill('test');
    await Promise.all([
        page.waitForURL(`${trustedOrigin}/`),
        page.locator('button[type="submit"]').click()
    ]);

    const createdTemplate = await page.evaluate(async () => {
        // eslint-disable-next-line no-undef
        const response = await globalThis.fetch('/rest/templates', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                // eslint-disable-next-line no-undef
                'X-CSRF-TOKEN': globalThis.csrfToken
            },
            body: JSON.stringify({
                name: 'Playwright Mosaico initialization fixture',
                description: 'Synthetic CI data',
                type: 'mosaico',
                tag_language: 'simple',
                namespace: 1,
                data: {
                    mosaicoTemplate: 1,
                    metadata: null,
                    model: null
                },
                html: '',
                text: ''
            })
        });

        return {
            status: response.status,
            id: await response.json()
        };
    });

    expect(createdTemplate.status).toBe(200);
    expect(createdTemplate.id).toBeGreaterThan(0);

    await page.goto(`${trustedOrigin}/templates/${createdTemplate.id}/edit`);

    const editor = page.frameLocator('iframe[src*="mosaico/editor"]');
    await expect(editor.locator('[data-ko-block]').first()).toBeAttached({timeout: 30000});
    expect(await editor.locator('[data-ko-block]').count()).toBeGreaterThan(0);
    await expect(editor.locator('#checkbadbrowsersframe')).toHaveCount(0);
    expect(dialogs).not.toContain('Update your browser!');
});

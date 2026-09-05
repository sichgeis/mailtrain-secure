'use strict';

const {expect, test} = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');
const knex = require('../../lib/knex');

const trustedOrigin = process.env.MAILTRAIN_TRUSTED_ORIGIN || 'http://127.0.0.1:3000';
const sandboxOrigin = process.env.MAILTRAIN_SANDBOX_ORIGIN || 'http://127.0.0.1:3003';
const publicOrigin = process.env.MAILTRAIN_PUBLIC_ORIGIN || 'http://127.0.0.1:3004';

test.afterAll(async () => {
    await knex.destroy();
});

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
    expect(sandboxResponse.headers()['content-security-policy']).not.toContain('\'unsafe-eval\'');

    const restrictedEditorResponse = await request.get(`${sandboxOrigin}/not-a-real-token/mosaico/editor`);
    expect(restrictedEditorResponse.headers()['content-security-policy']).not.toContain('\'unsafe-eval\'');

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

    // A password/role change increments this version; even a valid signed cookie
    // must no longer authenticate on the next request.
    await knex('users').where({id: 1}).increment('auth_version', 1);
    expect((await page.request.get(`${trustedOrigin}/rest/account`)).status()).not.toBe(200);
});

test('selectable tables expose clear pointer, keyboard, and selection affordances', async ({page}) => {
    await page.goto(`${trustedOrigin}/login`);
    await page.locator('#form_username').fill('admin');
    await page.locator('#form_password').fill('test');
    await Promise.all([
        page.waitForURL(`${trustedOrigin}/`),
        page.locator('button[type="submit"]').click()
    ]);

    await page.goto(`${trustedOrigin}/campaigns/create-regular`);
    const listsFieldset = page.getByRole('group', {name: 'Lists'});
    await expect(listsFieldset.getByRole('textbox')).toHaveCount(1);
    await listsFieldset.getByRole('button', {name: /add list/i}).click();
    await expect(listsFieldset.getByRole('textbox')).toHaveCount(2);
    const secondListInput = listsFieldset.getByRole('textbox').last();
    await expect(secondListInput).toBeVisible();
    await expect(secondListInput).toHaveCSS('cursor', 'pointer');
    await secondListInput.click();

    const selectorTable = secondListInput.locator('xpath=../following-sibling::div[1]');
    const table = selectorTable.locator('table');
    await expect(table).toBeVisible();
    await expect(table).toHaveAttribute('role', 'grid');
    await expect(selectorTable.locator('thead th').first()).toHaveText('Name');
    await expect(selectorTable.locator('tbody td').first()).not.toContainText('<div>');
    await expect(selectorTable.locator('tbody code').first()).toBeVisible();

    const firstRow = selectorTable.locator('tbody tr').first();
    const firstRowLabel = await firstRow.locator('td').first().innerText();
    await expect(firstRow).toHaveCSS('cursor', 'pointer');
    await expect(firstRow).toHaveAttribute('tabindex', '0');
    await expect(firstRow).toHaveAttribute('aria-selected', 'false');
    await firstRow.focus();
    await firstRow.press('Enter');
    await expect(secondListInput).toHaveValue(firstRowLabel);

    await secondListInput.click();
    await expect(firstRow).toHaveAttribute('aria-selected', 'true');
    const secondRow = selectorTable.locator('tbody tr').nth(1);
    const secondRowLabel = await secondRow.locator('td').first().innerText();
    await secondRow.focus();
    await secondRow.press(' ');
    await expect(secondListInput).toHaveValue(secondRowLabel);

    await page.goto(`${trustedOrigin}/lists`);
    const readOnlyRow = page.locator('table.dataTable tbody tr').first();
    await expect(readOnlyRow).toBeVisible();
    await expect(readOnlyRow).not.toHaveAttribute('tabindex', '0');
    await expect(readOnlyRow).not.toHaveCSS('cursor', 'pointer');
});

for (const variant of [
    {type: 'mosaico', data: {mosaicoTemplate: 1}},
    {type: 'mosaicoWithFsTemplate', data: {mosaicoFsTemplate: 'versafix-1'}}
]) {
    test(`${variant.type} template and campaign initialize inside the sandbox origin`, async ({page}) => {
        const dialogs = [];
        page.on('dialog', async dialog => {
            dialogs.push(dialog.message());
            if (dialog.type() === 'beforeunload') {
                await dialog.accept();
            } else {
                await dialog.dismiss();
            }
        });

        await page.goto(`${trustedOrigin}/login`);
        await page.locator('#form_username').fill('admin');
        await page.locator('#form_password').fill('test');
        await Promise.all([
            page.waitForURL(`${trustedOrigin}/`),
            page.locator('button[type="submit"]').click()
        ]);

        const createdTemplate = await page.evaluate(async variant => {
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
                    type: variant.type,
                    tag_language: 'simple',
                    namespace: 1,
                    data: variant.data,
                    html: '',
                    text: ''
                })
            });

            return {
                status: response.status,
                id: await response.json()
            };
        }, variant);

        expect(createdTemplate.status).toBe(200);
        expect(createdTemplate.id).toBeGreaterThan(0);

        const capability = await page.evaluate(async id => {
            const post = async (params, method = 'mosaico') => {
            // eslint-disable-next-line no-undef
                const response = await globalThis.fetch('/rest/restricted-access-token', {
                    method: 'POST',
                    // eslint-disable-next-line no-undef
                    headers: {'Content-Type': 'application/json', 'X-CSRF-TOKEN': globalThis.csrfToken},
                    body: JSON.stringify({method, params})
                });
                return {status: response.status, body: await response.json()};
            };
            return {
                invalid: await post({entityTypeId: 'unsupported', entityId: id}),
                wrongEditor: await post({entityTypeId: 'template', entityId: id}, 'codeeditor'),
                valid: await post({entityTypeId: 'template', entityId: id})
            };
        }, createdTemplate.id);
        expect(capability.invalid.status).toBe(403);
        expect(capability.wrongEditor.status).toBe(403);
        expect(capability.valid.status).toBe(200);
        const capabilityBase = `${sandboxOrigin}/${capability.valid.body}`;
        const deniedUpload = await page.request.post(`${capabilityBase}/mosaico/upload/template/999999999`, {
            multipart: {'files[]': {name: 'synthetic.txt', mimeType: 'text/plain', buffer: Buffer.from('synthetic rejected upload')}}
        });
        expect(deniedUpload.status()).toBe(403);
        for (const endpoint of ['account', 'access-token']) {
        // eslint-disable-next-line no-await-in-loop
            const response = await page.request.get(`${capabilityBase}/rest/${endpoint}`);
            expect(response.status()).toBe(404);
        }
        for (const endpoint of ['access-token-reset', 'restricted-access-token']) {
        // eslint-disable-next-line no-await-in-loop
            const response = await page.request.post(`${capabilityBase}/rest/${endpoint}`, {data: {}});
            expect(response.status()).toBe(404);
        }

        const editorResponsePromise = page.waitForResponse(response => {
            const url = new URL(response.url());
            return url.origin === sandboxOrigin && url.pathname === '/anonymous/mosaico/editor';
        });
        await page.goto(`${trustedOrigin}/templates/${createdTemplate.id}/edit`);

        const editorResponse = await editorResponsePromise;
        const editorCsp = editorResponse.headers()['content-security-policy'];
        expect(editorCsp).toContain('script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'');
        expect(editorCsp).toContain('sandbox allow-forms allow-modals allow-popups allow-same-origin allow-scripts');
        expect(editorCsp).toContain(`frame-ancestors ${trustedOrigin}`);

        const editor = page.frameLocator('iframe[src*="mosaico/editor"]');
        await expect(editor.locator('a[href="#toolblocks"]')).toBeVisible({timeout: 30000});
        await expect(editor.locator('[title*="Click or drag to add this block"]').first()).toBeVisible();
        await expect(editor.locator('#checkbadbrowsersframe')).toHaveCount(0);
        expect(dialogs).not.toContain('Update your browser!');

        const [templateSaved] = await Promise.all([
            page.waitForResponse(response => response.request().method() === 'PUT' && new URL(response.url()).pathname === `/rest/templates/${createdTemplate.id}`),
            page.locator('a[title="Save"]').click()
        ]);
        expect(templateSaved.status()).toBe(200);
        await page.reload();
        await expect(page.frameLocator('iframe[src*="mosaico/editor"]').locator('a[href="#toolblocks"]')).toBeVisible();

        // Campaign editing must get explicit scoped capabilities, not rely on an
        // unsupported factory returning an unrestricted identity.
        const campaign = await page.evaluate(async templateId => {
        // eslint-disable-next-line no-undef
            const response = await globalThis.fetch('/rest/campaigns', {
                method: 'POST',
                // eslint-disable-next-line no-undef
                headers: {'Content-Type': 'application/json', 'X-CSRF-TOKEN': globalThis.csrfToken},
                body: JSON.stringify({name: 'Synthetic editor campaign', namespace: 1, type: 1, source: 3,
                    send_configuration: 1, lists: [{list: 1}], data: {sourceTemplate: templateId}})
            });
            return {status: response.status, id: await response.json()};
        }, createdTemplate.id);
        expect(campaign.status, JSON.stringify(campaign.id)).toBe(200);
        await page.goto(`${trustedOrigin}/campaigns/${campaign.id}/content`);
        await expect(page.frameLocator('iframe[src*="mosaico/editor"]').locator('a[href="#toolblocks"]')).toBeVisible({timeout: 30000});

        const [campaignSaved] = await Promise.all([
            page.waitForResponse(response => response.request().method() === 'PUT' && new URL(response.url()).pathname === `/rest/campaigns-content/${campaign.id}`),
            page.locator('a[title="Save"]').click()
        ]);
        expect(campaignSaved.status()).toBe(200);
        await page.reload();
        await expect(page.frameLocator('iframe[src*="mosaico/editor"]').locator('a[href="#toolblocks"]')).toBeVisible();

        const scopedResource = `${capabilityBase}/mosaico/upload/template/${createdTemplate.id}`;
        expect((await page.request.get(scopedResource)).status()).toBe(200);
        expect((await page.request.get(`${capabilityBase}/mosaico/templates/1/index.html`)).status()).toBe(variant.type === 'mosaico' ? 200 : 403);
        const logoutStatus = await page.evaluate(async () => {
        // eslint-disable-next-line no-undef
            const response = await globalThis.fetch('/rest/logout', {
                method: 'POST',
                // eslint-disable-next-line no-undef
                headers: {'X-CSRF-TOKEN': globalThis.csrfToken}
            });
            return response.status;
        });
        expect(logoutStatus).toBe(200);
        expect((await page.request.get(scopedResource, {maxRedirects: 0})).status()).toBe(302);
    });
}

test('a real Mosaico image response persists across cache reconciliation', async ({request}) => {
    test.setTimeout(60000); // Two intentional five-second cache writes plus reconciliation waits.
    const cacheType = 'mosaico-images';
    const params = '37,19';
    const sourceFilename = 'cache-persistence-fixture.png';
    const sourceRelativeUrl = `files/mosaicoTemplate/file/1/${sourceFilename}`;
    const sourceUrl = `${publicOrigin}/${sourceRelativeUrl}`;
    const cacheKey = `${sourceRelativeUrl}_resize_${params}`;
    const cacheDir = path.join(__dirname, '..', '..', 'files', 'cache', cacheType);
    const durableDir = path.join(__dirname, '..', '..', 'files', 'mosaicoTemplate', 'file', '1');
    const durableFile = path.join(durableDir, sourceFilename);
    const sourceBytes = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');

    await knex('file_cache').where({type: cacheType, key: cacheKey}).del();
    await knex('files_mosaico_template_file').where({entity: 1, filename: sourceFilename}).del();
    await fs.mkdir(cacheDir, {recursive: true});
    await fs.mkdir(durableDir, {recursive: true});
    await fs.writeFile(durableFile, sourceBytes);
    await knex('files_mosaico_template_file').insert({
        entity: 1,
        filename: sourceFilename,
        originalname: sourceFilename,
        mimetype: 'image/png',
        size: sourceBytes.length
    });

    const response = await request.get(`${trustedOrigin}/mosaico/img?src=${encodeURIComponent(sourceUrl)}&method=resize&params=${params}`);
    expect(response.status()).toBe(200);
    expect((await response.body()).length).toBeGreaterThan(0);

    // The legacy writer intentionally waits five seconds before finalizing. Wait
    // through that delay and at least one one-second test reconciliation pass.
    await new Promise(resolve => setTimeout(resolve, 7000));

    const row = await knex('file_cache').where({type: cacheType, key: cacheKey}).first();
    expect(row).toBeDefined();

    const cachedFile = path.join(cacheDir, row.id.toString());
    expect((await fs.stat(cachedFile)).size).toBeGreaterThan(0);

    await new Promise(resolve => setTimeout(resolve, 1500));
    expect(await knex('file_cache').where({id: row.id}).first()).toBeDefined();
    expect((await fs.stat(cachedFile)).size).toBeGreaterThan(0);

    // Reproduce a cache entry poisoned while an image decoder was absent. A
    // cache hit must invalidate the empty row/file and regenerate from the
    // durable original instead of serving the empty response forever.
    await fs.truncate(cachedFile, 0);
    await knex('file_cache').where({id: row.id}).update({size: 0});

    const regeneratedResponse = await request.get(`${trustedOrigin}/mosaico/img?src=${encodeURIComponent(sourceUrl)}&method=resize&params=${params}`);
    expect(regeneratedResponse.status()).toBe(200);
    expect((await regeneratedResponse.body()).length).toBeGreaterThan(0);

    await new Promise(resolve => setTimeout(resolve, 7000));
    const regeneratedRow = await knex('file_cache').where({type: cacheType, key: cacheKey}).first();
    expect(regeneratedRow).toBeDefined();
    expect(regeneratedRow.id).not.toBe(row.id);
    expect(regeneratedRow.size).toBeGreaterThan(0);
    expect(await knex('file_cache').where({id: row.id}).first()).toBeUndefined();
    expect(await fs.stat(cachedFile).then(() => null, err => err.code)).toBe('ENOENT');

    const regeneratedFile = path.join(cacheDir, regeneratedRow.id.toString());
    expect((await fs.stat(regeneratedFile)).size).toBe(regeneratedRow.size);

    await new Promise(resolve => setTimeout(resolve, 1500));
    expect(await knex('file_cache').where({id: regeneratedRow.id}).first()).toBeDefined();
    expect((await fs.stat(regeneratedFile)).size).toBe(regeneratedRow.size);

    await knex('file_cache').where({id: regeneratedRow.id}).del();
    await fs.unlink(regeneratedFile);
    await knex('files_mosaico_template_file').where({entity: 1, filename: sourceFilename}).del();
    await fs.unlink(durableFile);
});

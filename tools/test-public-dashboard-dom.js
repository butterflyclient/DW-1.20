/* Run the served dashboard JavaScript in real Chromium on isolated fixture data. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const {chromium} = require('playwright');

async function main() {
    const args = Object.fromEntries(process.argv.slice(2).reduce((out, value, index, all) => {
        if (value.startsWith('--')) out.push([value.slice(2), all[index + 1]]);
        return out;
    }, []));
    assert(args.url && args.output);
    const target = new URL(args.url);
    assert(['127.0.0.1', 'localhost'].includes(target.hostname), 'Use an isolated loopback backend');
    const htmlResponse = await fetch(target);
    assert(htmlResponse.ok);
    const html = await htmlResponse.text();
    const statsResponse = await fetch(new URL('/stats.json', target));
    assert(statsResponse.ok);
    const original = await statsResponse.json();
    assert(original.activity.matches.length > 0, 'Fixture needs a published match');
    const checks = [];
    const browser = await chromium.launch({headless: true,
        ...(args['browser-executable'] ? {executablePath: args['browser-executable']} : {})});
    try {
        const cases = [
            {name: 'pending_ballot_manual_fill', start: false, fill: true, enabled: true, click: true},
            {name: 'ordinary_manual_waiting', start: true, fill: true, enabled: true},
            {name: 'automatic_fill_pending', start: false, fill: false, enabled: false},
            {name: 'automatic_fill_complete', start: true, fill: false, enabled: false},
            {name: 'full_waiting_roster', start: true, fill: true, enabled: false, full: true},
            {name: 'in_game', start: false, fill: false, enabled: false, playing: true},
            {name: 'manual_fill_requested', start: true, fill: true, enabled: false, requested: true},
        ];
        for (const test of cases) {
            const context = await browser.newContext();
            const page = await context.newPage();
            const failures = [];
            page.on('pageerror', error => failures.push(error.message));
            page.on('dialog', dialog => dialog.accept('fixture-operator-key'));
            const stats = structuredClone(original);
            const match = stats.activity.matches[0];
            Object.assign(match, {capacity: test.full ? 3 : 12, occupied_slots: 3,
                can_start: test.start, can_fill_bots: test.fill,
                start_requested: false, bots_requested: !!test.requested,
                bot_count: test.requested ? 2 : 0,
                state: test.playing ? 'in_game' : 'intermission'});
            stats.activity.matches = [match];
            const requests = [];
            await page.route('**/stats.json', route => route.fulfill({
                contentType: 'application/json', body: JSON.stringify(stats)}));
            // Button events execute the actual requestStart implementation,
            // but every operator request remains inside this browser fixture.
            await page.route('**/operator/**', async route => {
                const request = route.request();
                requests.push({path: new URL(request.url()).pathname,
                    method: request.method(), headers: request.headers(), body: request.postData()});
                await route.fulfill({status: 202, contentType: 'application/json',
                    body: JSON.stringify({message: 'Fixture fill accepted.'})});
            });
            await page.goto(target.href, {waitUntil: 'networkidle'});
            await page.locator('#match-list .match-box').waitFor();
            const start = page.getByRole('button', {name: 'Start match', exact: true});
            const bots = page.getByRole('button', {name: test.requested ? 'Bots requested' : 'Add bots', exact: true});
            const count = page.getByRole('spinbutton', {name: 'Number of bots to add'});
            assert.equal(await start.count(), test.start ? 1 : 0, test.name);
            assert.equal(await bots.count(), test.fill ? 1 : 0, test.name);
            assert.equal(await count.count(), test.fill ? 1 : 0, test.name);
            if (test.fill) {
                assert.equal(await bots.isEnabled(), test.enabled, test.name);
                assert.equal(await count.isEnabled(), test.enabled, test.name);
                assert.equal(await count.getAttribute('max'), test.full ? '0' : '9', test.name);
            }
            if (test.click) {
                await count.fill('2');
                await bots.click();
                await page.getByText('Fixture fill accepted.', {exact: true}).waitFor();
                assert.equal(requests.length, 1);
                assert.equal(requests[0].path, '/operator/fill-bots');
                assert.equal(requests[0].method, 'POST');
                assert.equal(requests[0].headers['x-replay-operator'], 'fixture-operator-key');
                assert.deepEqual(JSON.parse(requests[0].body), {match_token: match.start_token, bot_count: 2});
                assert.equal(await bots.isEnabled(), false);
            } else {
                assert.equal(requests.length, 0);
            }
            assert.deepEqual(failures, [], test.name);
            checks.push(test.name);
            await context.close();
        }
    } finally {
        await browser.close();
    }
    fs.writeFileSync(args.output, JSON.stringify({passed: true, checks,
        dashboard_sha256: crypto.createHash('sha256').update(html).digest('hex'),
        real_browser_dom: true, operator_requests_intercepted: true,
        production_changed: false, native_game_verified: false}, null, 2) + '\n');
    console.log(`PASS: ${checks.length} real dashboard DOM control cases`);
}
main().catch(error => {console.error(error); process.exitCode = 1;});

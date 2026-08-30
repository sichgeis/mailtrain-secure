'use strict';

// Mosaico 0.17.5's isCompatible() also compares the exact serialized markup of
// a synchronously populated iframe. Modern Chromium can legitimately leave that
// iframe incomplete while the editor is itself embedded, producing a false
// incompatibility result. Keep the actual browser capability checks here; HTML
// serialization timing and attribute order are not browser capabilities.
const requiredFeatures = [
    ['matchMedia', browser => typeof browser.matchMedia !== 'undefined'],
    ['XMLHttpRequest 2', browser => 'XMLHttpRequest' in browser && 'withCredentials' in new browser.XMLHttpRequest()],
    ['ES5 strict mode', () => (function() { return this; })() === undefined],
    ['CSS borderRadius', browser => typeof browser.document.body.style.borderRadius !== 'undefined'],
    ['CSS boxShadow', browser => typeof browser.document.body.style.boxShadow !== 'undefined'],
    ['CSS boxSizing', browser => typeof browser.document.body.style.boxSizing !== 'undefined'],
    ['CSS backgroundSize', browser => typeof browser.document.body.style.backgroundSize !== 'undefined'],
    ['CSS backgroundOrigin', browser => typeof browser.document.body.style.backgroundOrigin !== 'undefined']
];

export function getMissingMosaicoBrowserFeatures(browser = window) {
    return requiredFeatures
        .filter(([, isAvailable]) => !isAvailable(browser))
        .map(([name]) => name);
}

export function isMosaicoBrowserSupported(browser = window) {
    const missingFeatures = getMissingMosaicoBrowserFeatures(browser);
    if (missingFeatures.length > 0) {
        console.warn('Missing browser features required by Mosaico:', missingFeatures.join(', '));
        return false;
    }

    return true;
}

'use strict';

const {JSDOM} = require('jsdom');

const removedElements = new Set([
    'script', 'iframe', 'object', 'embed', 'svg', 'math', 'base', 'link',
    'form', 'input', 'button', 'textarea', 'select', 'option', 'video', 'audio', 'source'
]);
const urlAttributes = new Set(['href', 'src', 'poster', 'background', 'action', 'formaction', 'xlink:href']);

function isSafeUrl(value, attribute) {
    const trimmed = String(value || '').trim();
    if (!trimmed) {
        return true;
    }
    if (trimmed.startsWith('#') || trimmed.startsWith('/') || trimmed.startsWith('./') || trimmed.startsWith('../')) {
        return true;
    }
    try {
        const protocol = new URL(trimmed).protocol;
        if (attribute === 'href') {
            return ['http:', 'https:', 'mailto:', 'tel:'].includes(protocol);
        }
        return ['http:', 'https:', 'cid:'].includes(protocol);
    } catch (err) {
        return false;
    }
}

function sanitizeStyle(value) {
    return String(value || '').split(';').map(part => part.trim())
        .filter(part => part && !/(?:url\s*\(|expression\s*\(|behavior\s*:|-moz-binding|@import)/i.test(part))
        .join('; ');
}

function sanitizeCssDeclarations(style) {
    const declarations = [];
    for (const property of Array.from(style || [])) {
        const value = style.getPropertyValue(property);
        if (/(?:url\s*\(|expression\s*\(|behavior\s*:|-moz-binding|javascript\s*:|data\s*:)/i.test(value)) {
            continue;
        }
        declarations.push(`${property}:${value}${style.getPropertyPriority(property) ? ' !important' : ''}`);
    }
    return declarations.join(';');
}

function sanitizeCssRules(rules) {
    const output = [];
    for (const rule of Array.from(rules || [])) {
        if (rule.type === 1) {
            const declarations = sanitizeCssDeclarations(rule.style);
            if (declarations) {
                output.push(`${rule.selectorText}{${declarations}}`);
            }
        } else if (rule.type === 4 || rule.type === 12) {
            const nested = sanitizeCssRules(rule.cssRules);
            if (nested) {
                const name = rule.type === 4 ? 'media' : 'supports';
                output.push(`@${name} ${rule.conditionText}{${nested}}`);
            }
        }
    }
    return output.join('');
}

function isSafeViewportMeta(element) {
    return element.getAttribute('name') && element.getAttribute('name').toLowerCase() === 'viewport' &&
        /^[a-z0-9 .,_=;-]+$/i.test(element.getAttribute('content') || '');
}

function sanitizeUntrustedHtml(html) {
    const source = String(html || '');
    const fullDocument = /<(?:!doctype|html|head|body)\b/i.test(source);
    const dom = new JSDOM(fullDocument ? source : `<!doctype html><body>${source}</body>`);
    const document = dom.window.document;
    for (const element of Array.from(document.querySelectorAll('*'))) {
        if (element.localName === 'meta' && !isSafeViewportMeta(element)) {
            element.remove();
            continue;
        }
        if (element.localName === 'style') {
            const stylesheet = element.sheet ? sanitizeCssRules(element.sheet.cssRules) : '';
            if (!stylesheet) {
                element.remove();
            } else {
                element.textContent = stylesheet;
            }
            continue;
        }
        if (removedElements.has(element.localName)) {
            element.remove();
            continue;
        }
        for (const attribute of Array.from(element.attributes)) {
            const name = attribute.name.toLowerCase();
            if (name.startsWith('on') || ['srcdoc', 'nonce', 'integrity'].includes(name)) {
                element.removeAttribute(attribute.name);
            } else if (urlAttributes.has(name) && !isSafeUrl(attribute.value, name)) {
                element.removeAttribute(attribute.name);
            } else if (name === 'style') {
                const style = sanitizeStyle(attribute.value);
                if (style) {
                    element.setAttribute('style', style);
                } else {
                    element.removeAttribute('style');
                }
            }
        }
        if (element.localName === 'a' && element.hasAttribute('href')) {
            element.setAttribute('rel', 'noopener noreferrer');
        }
    }
    return fullDocument ? dom.serialize() : document.body.innerHTML;
}

module.exports = {
    sanitizeUntrustedHtml
};

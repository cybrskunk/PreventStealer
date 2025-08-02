// ==UserScript==
// @name         PreventStealerV2
// @namespace    http://tampermonkey.net/
// @version      1.3
// @description  An addon meant to help with determining whether a script is malicious, with intention to keep you safe.
// @author       Simon, Zpayer.
// @match        https://www.kogama.com/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=kogama.com
// @grant        none
// ==/UserScript==

(function() {
    'use strict';
 // would fetch from an online list but literally the counter-point of the inteded use, lol.
    const ALLOWED_PATTERNS = [
        /^\/api\/product\/subscription\/?$/,
        /^\/api\/product\/subscription\/promote-free\/?$/,
        /^\/api\/product\/gold\/?$/,
        /^\/api\/report\/types\/?$/,
        /^\/api\/report\/\d+\/\w+\/?$/,
        /^\/game\/\d+\/?$/,
        /^\/game\/published\/?$/,
        /^\/game\/\d+\/publish\/?$/,
        /^\/game\/gs-archive\/\?kogama_id=\d+&gs_id=\w+&title=[^&]+$/,
        /^\/user\/\d+\/?$/,
        /^\/user\/\d+\/game\/?$/,
        /^\/user\/\d+\/friend\/?$/,
        /^\/user\/\d+\/invitations\/?$/,
        /^\/user\/\d+\/password\/?$/,
        /^\/user\/\d+\/avatar\/\w+\/?$/,
        /^\/user\/\d+\/avatar\/?$/,
        /^\/user\/\d+\/username\/?$/,
        /^\/user\/\d+\/username\/\?username=\w+$/,
        /^\/user\/username\/\?username=\w+$/,
        /^\/user\/\d+\/email\/?$/,
        /^\/user\/\d+\/password-reset\/?$/,
        /^\/user\/\d+\/policy-accepted\/?$/,
        /^\/user\/\d+\/claim-daily-gold\/?$/,
        /^\/user\/\d+\/password-reset-required\/?$/,
        /^\/\d+badge\/\w+\/?$/,
        /^\/\d+badge\/\w+\/read\/?$/,
        /^\/api\/feed\/\d+\/?$/,
        /^\/api\/emote\/\d+\/?$/,
        /^\/api\/emote\/\d+\/\w+\/?$/,
        /^\/api\/emote\/emote-set\/?$/,
        /^\/api\/emote\/emote-set\/\d+\/?$/,
        /^\/api\/emote\/emote-set-emote\/?$/,
        /^\?emote-set-id=\d+$/,
        /^\/api\/emote\/emote-set-emote\/\d+\/?$/,
        /^\/api\/emote\/emote-set-transfer\/?$/,
        /^\/api\/app\/regions\/?$/,
        /^\/api\/spin\/data\/?$/,
        /^\/api\/news\/\d+\/?$/,
        /^\/api\/news\/unread\/?$/,
        /^\/model\/market\/?$/,
        /^\/model\/market\/\d+\/?$/,
        /^\/api\/shop\/\d+\/?$/,
        /^\/\d+\/comment\/?$/,
        /^\/api\/feed\/\d+\/comment\/?$/,
        /^\/game\/\d+\/comment\/?$/,
        /^\/server\/game\/?$/,
        /^\/server\/project\/?$/,
        /^\/server\/character\/?$/,
        /^\/locator\/session\/?$/,
        /^\/locator\/session\/\d+\/ping\/?$/,
        /^\/locator\/session\/\d+\/leave\/?$/,
        /^\/locator\/session\/\d+\/?$/,
        /^\/locator\/session\/\d+\/reauth\/?$/,
        /^\/api\/reward\/game-play\/?$/,
        /^\/v1\/api\/reward\/game-play\/?$/,
        /^\/v1\/api\/reward\/game-data\/?$/,
        /^\/v1\/api\/reward\/published\/?$/,
        /^\/chat\/\w+\/?$/,
        /^\/chat\/\d+\/history\/\w+\/?$/,
        /^\/user\/\d+\/friend\/chat\/?$/,
        /^\/user\/\d+\/friend\/chat\/\w+\/?$/,
        /^\/v1\/user\/\d+\/ping\/?$/,
        /^\/user\/\d+\/pulse\/?$/,
        /^\/v1\/stat\/p\/?$/,
        /^\/api\/onboarding\/\d+\/?$/,
        /^\/v1\/notify\/c\/\?token=\d+&generation=[^&]+$/,
        /^\/v1\/notify\/c\/seen\/\?token=\d+&generation=[^&]+$/,
        /^\/v1\/payment\/stripe\/charge\/?$/,
        /^\/help\/install\/chrome-help-sections\/?$/,
        /^\?version=\d+$/,
        /^\/help\/install\/other-help-sections\/?$/,
        /^\/profile\/\d+\/?$/,
        /^\/games\/profile\/\d+\/?$/,
        /^\/games\/play\/\d+\/?$/,
        /^\?local=1$/,
        /^\/games\/?$/,
        /^\/build\/\d+\/project\/?$/,
        /^\/build\/\d+\/project\/\w+\/?$/,
        /^\/build\/\d+\/project\/\w+\/edit\/?$/,
        /^\/purchase\/?$/,
        /^\/login\/\?next=[^&]+$/,
        /^\/register\/?$/,
        /^\/register\/\?xp=\d+&signature=\w+$/,
        /^\/auth\/logout\/?$/,
        /^\/page\/disconnected\/\?reason=idle$/,
        /^\/page\/embed\/disconnected\/\?reason=idle$/,
        /^\/page\/disconnected\/?$/,
        /^\/page\/webgl-frame\/?$/,
        /^\/help\/install\/kogama-launcher-windows\/?$/,
        /^\/page\/new-plugin-installed-reward\/?$/,
        /^\/news\/\w+\/?$/,
        /^\/subscription\/subscribe\/?$/,
        /^\/payment\/options\/?$/,
        /^\/payment\/billing-information\/?$/,
        /^\/payment\/thank-you\/?$/,
        /^\/payment\/addons\/?$/,
        /^\/subscription\/manage\/?$/,
        /^\/marketplace\/?$/,
        /^\/locator\/session\/\?objectID=\d+&profileID=\d+&lang=\w+_\w+&type=\w+&referrer=\w+$/
    ];
    function isAllowed(url) {
        if (!url.startsWith('http')) return true;
        const path = new URL(url).pathname + new URL(url).search;
        return ALLOWED_PATTERNS.some(pattern => pattern.test(path));
    }

    // notification - this can be disabled but I'm keeping it for clarity. Perhaps you're not as experienced.
    function logBlockedRequest(type, url) {
        console.warn(`[Security] Blocked ${type} to:`, url);
        const notification = document.createElement('div');
        notification.style.position = 'fixed';
        notification.style.bottom = '10px';
        notification.style.right = '10px';
        notification.style.backgroundColor = '#ff4444';
        notification.style.color = 'white';
        notification.style.padding = '10px';
        notification.style.borderRadius = '5px';
        notification.style.zIndex = '9999';
        notification.style.maxWidth = '300px';
        notification.innerHTML = `
            <strong>Blocked ${type} request</strong><br>
            ${url}<br>
            <small>Check console for more details</small>
        `;
        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 5000);
    }
    const originalFetch = window.fetch;
    window.fetch = function(resource, init) {
        const url = typeof resource === 'string' ? resource : resource.url;
        if (!isAllowed(url)) {
            logBlockedRequest('fetch', url);
            return Promise.reject(new Error(`Request to ${url} blocked by security policy`));
        }
        return originalFetch.apply(this, arguments);
    };
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        if (!isAllowed(url)) {
            logBlockedRequest('XHR', url);
            throw new Error(`Request to ${url} blocked by security policy`);
        }
        return originalOpen.apply(this, arguments);
    };
    const originalWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
        if (!isAllowed(url)) {
            logBlockedRequest('WebSocket', url);
            throw new Error(`WebSocket connection to ${url} blocked by security policy`);
        }
        return new originalWebSocket(url, protocols);
    };

    console.log('%cPreventStlrV2 loaded', 'color: #4CAF50; font-weight: bold;');
})();

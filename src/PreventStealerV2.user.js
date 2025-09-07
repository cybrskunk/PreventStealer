// ==UserScript==
// @name         PreventStealerV3
// @namespace    http://tampermonkey.net/
// @version      1.8
// @description  Detects and blocks malicious password or logout requests, with detailed notifications
// @author       Simon, Zpayer
// @match        https://www.kogama.com/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=kogama.com
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

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

    const BLOCKED_ENDPOINTS = [
        /\/auth\/logout\/?$/,          // block logout attempts
        /\/password-reset\/?$/,        // sensitive
        /\/password-reset-required\/?$/, // password exploit change
        /\/password\/?$/               // password change
    ];

    const BLOCKED_METHODS = ['PUT', 'POST'];
    const SUSPICIOUS_HEADERS = ['authorization', 'x-csrf-token', 'x-requested-with'];

    function isAllowed(url) {
        if (!url.startsWith('http')) return true;
        const u = new URL(url, location.origin);
        const path = u.pathname + u.search;
        return ALLOWED_PATTERNS.some(pattern => pattern.test(path));
    }

    function isBlockedEndpoint(url) {
        return BLOCKED_ENDPOINTS.some(p => p.test(url));
    }

    function isSuspiciousRequest(init) {
        if (!init) return false;
        if (BLOCKED_METHODS.includes(init.method?.toUpperCase())) return true;

        if (init.headers) {
            const headers = init.headers instanceof Headers ?
                Object.fromEntries(init.headers.entries()) :
                init.headers;

            return SUSPICIOUS_HEADERS.some(h => headers[h] && /bearer|token/i.test(headers[h]));
        }
        return false;
    }

    function extractPayload(init) {
        if (!init) return '';
        let data = '';
        if (init.method) data += `Method: ${init.method}\n`;
        if (init.body) {
            try {
                const body = typeof init.body === 'string' ? init.body : JSON.stringify(init.body);
                data += `Payload: ${body.slice(0,200)}${body.length>200?'...':''}\n`;
            } catch {}
        }
        return data.trim();
    }

    function logBlockedRequest(source, url, extra = '') {
        console.warn(`[Security] Blocked from ${source}:`, url, extra);

        const notification = document.createElement('div');
        Object.assign(notification.style, {
            position: 'fixed',
            bottom: '10px',
            right: '10px',
            backgroundColor: '#202124',
            color: '#f1f1f1',
            padding: '10px 14px',
            borderRadius: '6px',
            borderLeft: '4px solid #ff3b30',
            fontSize: '13px',
            zIndex: '99999',
            maxWidth: '320px',
            fontFamily: 'monospace',
            whiteSpace: 'pre-wrap',
            boxShadow: '0 3px 12px rgba(0,0,0,0.3)'
        });

        notification.innerHTML = `
            <div style="font-weight:bold;margin-bottom:4px;">🚫 Blocked ${source}</div>
            <div style="color:#bbb;font-size:12px;word-break:break-word;">${url}</div>
            ${extra ? `<div style="margin-top:6px;color:#aaa;font-size:11px;">${extra}</div>` : ''}
        `;

        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 6000);
    }

    // --- PATCH FETCH ---
    const originalFetch = window.fetch;
    window.fetch = function(resource, init) {
        const url = typeof resource === 'string' ? resource : resource.url;

        if (isBlockedEndpoint(url) || !isAllowed(url)) {
            const details = extractPayload(init);
            logBlockedRequest('fetch', url, details || 'Sensitive endpoint blocked');
            return Promise.reject(new Error(`Request blocked: ${url}`));
        }
        if (isSuspiciousRequest(init)) {
            logBlockedRequest('fetch', url, 'Suspicious headers or payload detected');
            return Promise.reject(new Error(`Suspicious fetch blocked: ${url}`));
        }
        if (url.includes('discord.com/api/webhooks')) {
            logBlockedRequest('fetch', url, 'Webhook request blocked');
            return Promise.reject(new Error('Webhook blocked'));
        }
        return originalFetch.apply(this, arguments);
    };

    // --- PATCH XHR ---
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        if (isBlockedEndpoint(url) || !isAllowed(url)) {
            logBlockedRequest('XHR', url, `Method: ${method}`);
            throw new Error(`XHR blocked: ${url}`);
        }
        return originalOpen.apply(this, arguments);
    };

    // --- PATCH WEBSOCKET ---
    const originalWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
        if (isBlockedEndpoint(url) || !isAllowed(url)) {
            logBlockedRequest('WebSocket', url);
            throw new Error(`WebSocket blocked: ${url}`);
        }
        return new originalWebSocket(url, protocols);
    };

    console.log('%c[ PREVENTSTEALERV3 ] Watching for suspicious logout/password traffic…', 'color:#ff3b30;font-weight:bold;');
})();

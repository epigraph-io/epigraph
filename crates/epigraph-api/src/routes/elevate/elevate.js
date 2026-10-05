// The elevation page's and the admin-act page's script (elevation plan EL-5,
// EL-12b). Served from the API
// binary under a CSP that forbids inline script, so everything the page does
// is here. It talks only to its own origin.
(function () {
  'use strict';

  var root = document.getElementById('ceremony');
  var button = document.getElementById('confirm');
  var status = document.getElementById('status');
  if (!root || !button || !status) {
    return;
  }
  // The elevation page names its ticket; the admin-act page names its own
  // base path (`/elevate/act/<id>`) and what it confirms.
  var base = root.getAttribute('data-base') ||
    ('/elevate/' + encodeURIComponent(root.getAttribute('data-ticket')));
  var noun = root.getAttribute('data-noun') === 'act' ? 'Not confirmed: ' : 'Not elevated: ';

  function say(text, kind) {
    status.textContent = text;
    status.className = kind || '';
  }

  function fromB64url(s) {
    var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) {
      b64 += '=';
    }
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out.buffer;
  }

  function toB64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function failure(resp) {
    return resp.json().then(
      function (body) {
        return (body && (body.detail || body.error)) || ('HTTP ' + resp.status);
      },
      function () {
        return 'HTTP ' + resp.status;
      }
    );
  }

  function confirmElevation() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      say('This browser does not support passkeys.', 'error');
      return;
    }
    button.disabled = true;
    say('Requesting a challenge...');
    fetch(base + '/challenge', { method: 'POST', credentials: 'omit' })
      .then(function (resp) {
        if (!resp.ok) {
          return failure(resp).then(function (why) { throw new Error(why); });
        }
        return resp.json();
      })
      .then(function (options) {
        var pk = options.publicKey;
        pk.challenge = fromB64url(pk.challenge);
        (pk.allowCredentials || []).forEach(function (c) {
          c.id = fromB64url(c.id);
        });
        say('Use your passkey and verify yourself (PIN or biometric)...');
        return navigator.credentials.get({ publicKey: pk });
      })
      .then(function (cred) {
        var body = {
          id: cred.id,
          rawId: toB64url(cred.rawId),
          type: cred.type,
          response: {
            authenticatorData: toB64url(cred.response.authenticatorData),
            clientDataJSON: toB64url(cred.response.clientDataJSON),
            signature: toB64url(cred.response.signature),
            userHandle: cred.response.userHandle ? toB64url(cred.response.userHandle) : null
          },
          extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
        };
        say('Verifying...');
        return fetch(base + '/assert', {
          method: 'POST',
          credentials: 'omit',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
      })
      .then(function (resp) {
        if (!resp.ok) {
          return failure(resp).then(function (why) { throw new Error(why); });
        }
        return resp.json().then(function (body) {
          say((body && body.detail) || 'Elevated.', 'ok');
        });
      })
      .catch(function (err) {
        say(noun + (err && err.message ? err.message : String(err)), 'error');
        button.disabled = false;
      });
  }

  button.addEventListener('click', confirmElevation);
})();

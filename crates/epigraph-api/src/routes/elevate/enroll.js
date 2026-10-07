// The passkey enrollment page's script (elevation plan EL-3). Served from the
// API binary under a CSP that forbids inline script, so everything the page
// does is here. It talks only to its own origin.
(function () {
  'use strict';

  var root = document.getElementById('ceremony');
  var button = document.getElementById('register');
  var status = document.getElementById('status');
  if (!root || !button || !status) {
    return;
  }
  var base = '/elevate/enroll/' + encodeURIComponent(root.getAttribute('data-enrollment'));

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

  function register() {
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
        pk.user.id = fromB64url(pk.user.id);
        (pk.excludeCredentials || []).forEach(function (c) {
          c.id = fromB64url(c.id);
        });
        say('Use your authenticator and verify yourself (PIN or biometric)...');
        return navigator.credentials.create({ publicKey: pk });
      })
      .then(function (cred) {
        var body = {
          id: cred.id,
          rawId: toB64url(cred.rawId),
          type: cred.type,
          response: {
            attestationObject: toB64url(cred.response.attestationObject),
            clientDataJSON: toB64url(cred.response.clientDataJSON),
            transports: cred.response.getTransports ? cred.response.getTransports() : undefined
          },
          extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
        };
        say('Verifying...');
        return fetch(base + '/finish', {
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
        say('Passkey registered. You can close this page.', 'ok');
      })
      .catch(function (err) {
        say('Registration failed: ' + (err && err.message ? err.message : String(err)), 'error');
        button.disabled = false;
      });
  }

  button.addEventListener('click', register);
})();

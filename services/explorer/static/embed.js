// EpiGraph Explorer: sign-in from an embedded page (plan §3.3).
//
// A Notion embed is a third-party iframe: the first-party SameSite=Lax
// session cookie is never sent to it, and EpiGraph's (Google's) sign-in pages
// refuse to be framed. So sign-in runs in a popup, and the session reaches
// the iframe through a single-use handoff code:
//
//   iframe: /auth/login (Sec-Fetch-Dest: iframe) renders #epx-embed-signin
//     → click opens /auth/login?mode=popup in a popup
//   popup: authorize → /auth/callback renders #epx-auth-popup with the code
//     → postMessage({code}) to window.opener, addressed to this origin only
//   iframe: checks event.origin and event.source, POSTs the code to
//     /auth/redeem (sets the SameSite=None; Partitioned cookie), continues
//
// This file plays whichever role its page asks for. All data arrives in
// data- attributes (CSP is script-src 'self': no inline script), and no
// token or code ever appears in a URL.

(() => {
  "use strict";

  const MSG_HANDOFF = "epx-auth-handoff";
  const MSG_ERROR = "epx-auth-error";
  // Upstream's authorize session lives 10 minutes; a popup still open after
  // that cannot succeed.
  const POPUP_TIMEOUT_MS = 10 * 60 * 1000;
  const CLOSED_POLL_MS = 500;
  // A closing popup's message and the poll that sees it closed are separate
  // tasks with no guaranteed order; wait this long before calling it a failure.
  const CLOSED_GRACE_MS = 1000;

  // ---- popup role: report the outcome to the opener and close ------------

  function popupRole(el) {
    const note = document.getElementById("epx-auth-popup-note");
    const lostContact = () => {
      if (!note) return;
      note.textContent =
        "This window lost contact with the page that opened it. Close it and sign in again from that page.";
      note.hidden = false;
    };

    const opener = window.opener;
    if (!opener || opener.closed) {
      lostContact();
      return;
    }
    const ok = el.dataset.status === "ok" && el.dataset.handoff;
    const message = ok
      ? { type: MSG_HANDOFF, code: el.dataset.handoff }
      : { type: MSG_ERROR, message: el.dataset.message || "" };
    try {
      // targetOrigin is our own origin: an opener on any other origin
      // (someone else's page that opened our login) never receives it.
      opener.postMessage(message, window.location.origin);
    } catch (_) {
      lostContact();
      return;
    }
    window.close();
  }

  // ---- iframe role: open the popup, receive the code, redeem it ----------

  function embedRole(button) {
    const status = document.getElementById("epx-embed-status");
    const loginUrl = button.dataset.login;
    const redeemUrl = button.dataset.redeem;
    const returnTo = button.dataset.returnTo;
    let active = null;

    const show = (text, isError) => {
      if (!status) return;
      status.textContent = text;
      status.classList.toggle("notice--warn", Boolean(isError));
      status.hidden = false;
    };

    const stop = () => {
      if (!active) return;
      clearTimeout(active.timer);
      clearInterval(active.poll);
      window.removeEventListener("message", active.onMessage);
      active = null;
      button.disabled = false;
    };

    const fail = (text) => {
      stop();
      show(text, true);
    };

    const redeem = (code) => {
      button.disabled = true;
      show("Signing you in…");
      fetch(redeemUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ code }).toString(),
      })
        .then((res) => {
          if (!res.ok) throw new Error(`redeem answered ${res.status}`);
          window.location.assign(returnTo);
        })
        .catch(() => {
          button.disabled = false;
          show(
            "Sign-in finished, but this embedded page could not keep the session. " +
              "Your browser may block cookies in embedded pages: open the Explorer in a new tab instead.",
            true,
          );
        });
    };

    const onMessage = (event) => {
      if (!active || event.origin !== window.location.origin || event.source !== active.popup) {
        return;
      }
      const data = event.data;
      if (!data || typeof data !== "object") return;
      if (data.type === MSG_HANDOFF && typeof data.code === "string" && data.code) {
        stop();
        redeem(data.code);
      } else if (data.type === MSG_ERROR) {
        fail(
          typeof data.message === "string" && data.message
            ? data.message
            : "Sign-in failed. Try again.",
        );
      }
    };

    button.addEventListener("click", () => {
      if (active) {
        active.popup.focus();
        return;
      }
      const popup = window.open(loginUrl, "epx-signin", "popup,width=520,height=720");
      if (!popup) {
        fail("Your browser blocked the sign-in window. Allow pop-ups for this page and try again.");
        return;
      }
      button.disabled = true;
      show("Finish signing in in the new window.");
      active = {
        popup,
        onMessage,
        closedSince: 0,
        timer: setTimeout(() => {
          try {
            popup.close();
          } catch (_) {
            /* already gone */
          }
          fail("Sign-in timed out. Try again.");
        }, POPUP_TIMEOUT_MS),
        poll: setInterval(() => {
          if (!active || !popup.closed) return;
          const now = Date.now();
          if (!active.closedSince) {
            active.closedSince = now;
          } else if (now - active.closedSince >= CLOSED_GRACE_MS) {
            // EpiGraph's own sign-in errors (an account off the allowlist,
            // a denied consent) end on the API's origin and never come
            // back here; the viewer closing the window is all we see.
            fail(
              "The sign-in window closed before sign-in finished. " +
                "If it showed an error, this account may not be allowed to use EpiGraph; otherwise try again.",
            );
          }
        }, CLOSED_POLL_MS),
      };
      window.addEventListener("message", onMessage);
    });

    button.hidden = false;
  }

  const popupEl = document.getElementById("epx-auth-popup");
  if (popupEl) {
    popupRole(popupEl);
    return;
  }
  const button = document.getElementById("epx-embed-signin");
  if (button) embedRole(button);
})();

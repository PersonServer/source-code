// Passkey ceremonies. The server speaks the WebAuthn Level 3 JSON forms:
// PublicKeyCredentialCreationOptionsJSON / RequestOptionsJSON in, and
// PublicKeyCredential.toJSON() out. No other script runs on these pages.
(function () {
  "use strict";
  var status = document.getElementById("passkey-status");
  function say(msg, bad) { if (status) { status.textContent = msg; status.className = bad ? "status warn" : "status"; } }
  async function postJson(url, body, csrf) {
    var headers = { "content-type": "application/json" };
    if (csrf) headers["x-csrf"] = csrf;
    var r = await fetch(url, { method: "POST", headers: headers, body: JSON.stringify(body), credentials: "same-origin" });
    var data = null;
    try { data = await r.json(); } catch (e) { data = null; }
    if (!r.ok) throw new Error((data && (data.detail || data.error)) || ("HTTP " + r.status));
    return data;
  }
  function supported() {
    return window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON && PublicKeyCredential.parseRequestOptionsFromJSON;
  }
  var create = document.getElementById("passkey-create");
  if (create) create.addEventListener("click", async function () {
    if (!supported()) { say("This browser does not support the WebAuthn JSON API. Please use a current browser.", true); return; }
    create.disabled = true; say("Waiting for your authenticator…");
    try {
      var options = await postJson(create.dataset.options, {}, create.dataset.csrf);
      var cred = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) });
      var done = await postJson(create.dataset.finish, cred.toJSON(), create.dataset.csrf);
      say("Passkey registered. Redirecting…");
      window.location.href = done.redirect || "/";
    } catch (e) { say("Could not create a passkey: " + (e && e.message ? e.message : e), true); create.disabled = false; }
  });
  var get = document.getElementById("passkey-get");
  if (get) get.addEventListener("click", async function () {
    if (!supported()) { say("This browser does not support the WebAuthn JSON API. Please use a current browser.", true); return; }
    get.disabled = true; say("Waiting for your authenticator…");
    try {
      var options = await postJson(get.dataset.options, {});
      var cred = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) });
      var done = await postJson(get.dataset.finish, { credential: cred.toJSON(), next: get.dataset.next || "" });
      say("Signed in. Redirecting…");
      window.location.href = done.redirect || "/";
    } catch (e) { say("Could not sign in: " + (e && e.message ? e.message : e), true); get.disabled = false; }
  });
})();

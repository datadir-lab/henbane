// probe.js is the client side of jsprobe. It reads automation tells, optionally waits
// for human-like input, optionally computes a device fingerprint, and POSTs the report
// to HB_VERIFY (injected by the server, along with HB_TIER). On a 204 it reloads so the
// now-passed client reaches the site. It collects nothing that is sent anywhere but the
// operator's own Henbane. Tiers: 0 passive, 1 behavioural, 2 device.
(function () {
  function webglVendor() {
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return "";
      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      return ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : "";
    } catch (e) {
      return "";
    }
  }

  function deviceHash() {
    try {
      var c = document.createElement("canvas");
      c.width = 220;
      c.height = 40;
      var ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#069";
      ctx.fillText("henbane-probe-☃-0123", 2, 2);
      var s = c.toDataURL() + "|" + webglVendor() + "|" + navigator.userAgent + "|" +
        screen.width + "x" + screen.height + "x" + (screen.colorDepth || 0) + "|" +
        (navigator.languages || []).join(",") + "|" + (navigator.hardwareConcurrency || 0);
      // djb2-xor; a stable identity bucket, not a cryptographic hash.
      var h = 5381;
      for (var i = 0; i < s.length; i++) h = (((h << 5) + h) ^ s.charCodeAt(i)) >>> 0;
      return h.toString(16);
    } catch (e) {
      return "";
    }
  }

  var signals = {
    webdriver: navigator.webdriver === true,
    webglVendor: webglVendor(),
    hasChrome: !!window.chrome,
    humanInput: false,
    deviceHash: HB_TIER >= 2 ? deviceHash() : ""
  };

  function fail() {
    var m = document.getElementById("hb-msg");
    if (m) m.textContent = "Verification failed.";
  }

  function send() {
    fetch(HB_VERIFY, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(signals),
      credentials: "same-origin"
    }).then(function (r) {
      if (r.status === 204) location.reload();
      else fail();
    }).catch(function () {
      setTimeout(send, 1500);
    });
  }

  if (HB_TIER >= 1) {
    // Behavioural: wait for a few human-like input events spread over a brief window
    // before reporting humanInput=true. A client that never interacts times out and is
    // reported with humanInput=false (failing the behavioural check).
    var seen = 0;
    var start = Date.now();
    var events = ["mousemove", "pointermove", "touchstart", "scroll", "keydown"];
    function cleanup() {
      events.forEach(function (e) { window.removeEventListener(e, onInput, true); });
    }
    function onInput() {
      seen++;
      if (seen >= 3 && Date.now() - start > 400) {
        signals.humanInput = true;
        cleanup();
        send();
      }
    }
    events.forEach(function (e) { window.addEventListener(e, onInput, true); });
    setTimeout(function () { cleanup(); send(); }, 8000);
  } else {
    send();
  }
})();

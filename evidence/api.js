/* Lapisan fetch tipis: api.post(path, body) -> {ok, status, message, data}. CSRF dari <meta name="csrf-token">. */
(function () {
  var meta = document.querySelector('meta[name="csrf-token"]');
  var base = (document.documentElement.getAttribute('data-base') || '').replace(/\/$/, '');
  window.api = {
    post: function (path, body) {
      return fetch(base + path, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRF-Token': meta ? meta.getAttribute('content') : ''
        },
        body: JSON.stringify(body || {})
      }).then(function (res) {
        return res.json().then(function (j) { j.status = res.status; return j; }, function () { return { ok: false, status: res.status, message: 'Respons server tidak valid.', data: {} }; });
      }).catch(function () {
        return { ok: false, status: 0, network: true, message: 'Tidak dapat terhubung ke server. Coba lagi.', data: {} };
      });
    }
  };
  window.toast = function (msg, ok) {
    var box = document.getElementById('toasts');
    if (!box) {
      box = document.createElement('div');
      box.id = 'toasts';
      box.className = 'fixed bottom-4 right-4 z-[100] flex flex-col gap-2 max-w-[90vw]';
      box.setAttribute('aria-live', 'polite');
      document.body.appendChild(box);
    }
    var t = document.createElement('div');
    t.className = 'rounded-xl px-4 py-3 shadow-bento-hover border text-sm font-medium ' + (ok === false ? 'bg-red-100 border-danger/40 text-danger' : 'bg-pastel-green border-green-ink/30');
    t.textContent = msg;
    box.appendChild(t);
    setTimeout(function () { t.remove(); }, 3500);
  };
})();

/* Marketplace: beli via api.js tanpa reload. Tanpa JS, form POST biasa tetap berfungsi. */
(function () {
  var shop = document.getElementById('shop');
  if (!shop || !window.api) { return; }
  var nf = new Intl.NumberFormat('id-ID');
  function stockText(s) { return s === null ? 'Stok tak terbatas' : (s > 0 ? 'Stok: ' + s : 'Stok habis'); }

  shop.addEventListener('submit', function (e) {
    var form = e.target.closest('form[data-buy]');
    if (!form) { return; }
    e.preventDefault();
    var btn = form.querySelector('button');
    if (btn.disabled) { return; }
    var old = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Memproses...';
    window.api.post('/api/marketplace/purchase', { reward_id: parseInt(form.getAttribute('data-buy'), 10) }).then(function (r) {
      var soldOut = false;
      if (r.ok) {
        document.querySelectorAll('[data-coins]').forEach(function (el) { el.textContent = nf.format(r.data.coins); });
        var el = document.querySelector('[data-stock="' + r.data.reward_id + '"]');
        if (el) { el.textContent = stockText(r.data.stock); }
        soldOut = r.data.stock !== null && r.data.stock <= 0;
        window.toast(r.message, true);
        addHistoryRow(form, r.data);
      } else if (r.status === 401 || r.status === 419) {
        window.toast('Sesi berakhir. Silakan masuk lagi.', false);
        var base = (document.documentElement.getAttribute('data-base') || '').replace(/\/$/, '');
        setTimeout(function () { window.location.href = base + '/login'; }, 1200);
        return;
      } else if (r.network) {
        window.toast('Koneksi terputus. Cek riwayat pembelian sebelum mencoba lagi.', false);
        refreshHistory();
      } else if (r.status === 409 && /stok/i.test(r.message || '')) {
        var se = document.querySelector('[data-stock="' + form.getAttribute('data-buy') + '"]');
        if (se) { se.textContent = 'Stok habis'; }
        window.toast(r.message, false);
        soldOut = true;
      } else {
        window.toast(r.message, false); // termasuk 409 koin kurang: tombol tetap aktif
      }
      if (soldOut) { btn.textContent = 'Habis'; return; } // tetap nonaktif
      btn.disabled = false;
      btn.textContent = old;
    });
  });

  function refreshHistory() {
    var body = document.getElementById('histBody');
    if (!body || !window.fetch) { return; }
    fetch(window.location.href, { credentials: 'same-origin', headers: { 'Accept': 'text/html' } })
      .then(function (res) { return res.text(); })
      .then(function (html) {
        var nb = new DOMParser().parseFromString(html, 'text/html').getElementById('histBody');
        if (nb) { body.innerHTML = nb.innerHTML; }
      })
      .catch(function () { window.toast('Muat ulang halaman untuk melihat riwayat terbaru.', false); });
  }

  function addHistoryRow(form, d) {
    var body = document.getElementById('histBody');
    if (!body) { return; }
    var empty = document.getElementById('histEmpty');
    if (empty) { empty.remove(); }
    var cost = form.getAttribute('data-cost');
    var tr = document.createElement('tr');
    tr.className = 'border-t border-lavender/50';
    [form.getAttribute('data-name'), nf.format(parseInt(cost, 10)), 'Baru saja'].forEach(function (t, i) {
      var td = document.createElement('td'); td.className = 'p-3' + (i === 1 ? ' stat' : ''); td.textContent = t; tr.appendChild(td);
    });
    var td = document.createElement('td'); td.className = 'p-3';
    var chip = document.createElement('span'); chip.className = 'chip bg-pastel-yellow'; chip.textContent = 'Menunggu dosen';
    td.appendChild(chip); tr.appendChild(td);
    body.insertBefore(tr, body.firstChild);
  }
})();

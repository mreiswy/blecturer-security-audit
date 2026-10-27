/* Sidebar responsif: burger membuka/menutup, aria-expanded diperbarui. */
(function () {
  var sb = document.getElementById('sidebar');
  var sc = document.getElementById('scrim');
  var bg = document.getElementById('burger');
  if (!sb || !bg) { return; }
  var desktop = window.matchMedia('(min-width: 1024px)');
  function isOpen() { return !sb.classList.contains('-translate-x-full'); }
  // Tertutup di mobile: tidak bisa difokus (inert) dan disembunyikan dari pembaca layar.
  function sync() {
    var hidden = !desktop.matches && !isOpen();
    if (hidden) { sb.setAttribute('inert', ''); sb.setAttribute('aria-hidden', 'true'); }
    else { sb.removeAttribute('inert'); sb.removeAttribute('aria-hidden'); }
  }
  function toggle(open) {
    var wasOpen = isOpen();
    sb.classList.toggle('-translate-x-full', !open);
    if (sc) { sc.classList.toggle('hidden', !open); }
    bg.setAttribute('aria-expanded', open ? 'true' : 'false');
    bg.setAttribute('aria-label', open ? 'Tutup menu' : 'Buka menu');
    sync();
    if (open && !wasOpen) {
      var first = sb.querySelector('a[href], button');
      if (first) { first.focus(); }
    } else if (!open && wasOpen) {
      bg.focus(); // fokus kembali ke burger saat menu ditutup
    }
  }
  bg.addEventListener('click', function () { toggle(!isOpen()); });
  if (sc) { sc.addEventListener('click', function () { toggle(false); }); }
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && isOpen() && !desktop.matches) { toggle(false); } });
  if (desktop.addEventListener) { desktop.addEventListener('change', sync); } else { desktop.addListener(sync); }
  sync();
})();

/* Lebar progress bar dari data-pct (CSP melarang atribut style inline). */
document.querySelectorAll('[data-pct]').forEach(function (el) {
  var p = parseInt(el.getAttribute('data-pct'), 10);
  if (!isNaN(p)) { el.style.width = Math.max(0, Math.min(100, p)) + '%'; }
});

/* Konfirmasi sebelum kirim form berbahaya: <form data-confirm="pesan">. */
document.addEventListener('submit', function (e) {
  var msg = e.target && e.target.getAttribute && e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) { e.preventDefault(); }
});

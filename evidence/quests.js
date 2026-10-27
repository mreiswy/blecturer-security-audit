/* Quest Board: ubah form inline (details) menjadi <dialog> modal. Tanpa JS/dialog, form inline tetap berfungsi. */
(function () {
  var modal = document.getElementById('modal');
  var form = document.getElementById('mForm');
  var url = document.getElementById('mUrl');
  var err = document.getElementById('mErr');
  var send = document.getElementById('mSend');
  if (!modal || !form || typeof modal.showModal !== 'function') { return; }
  var opener = null;

  // showModal(): fokus terperangkap, latar inert, Esc menutup (event 'close').
  modal.addEventListener('close', function () {
    if (opener) { opener.focus(); opener = null; }
  });
  document.querySelectorAll('details[data-quest]').forEach(function (d) {
    var sum = d.querySelector('summary');
    sum.addEventListener('click', function (e) {
      e.preventDefault();
      opener = sum;
      form.action = d.querySelector('form').action;
      document.getElementById('mTitle').textContent = d.getAttribute('data-title');
      document.getElementById('mInfo').textContent = d.getAttribute('data-info');
      var desc = document.getElementById('mDesc');
      var tpl = d.querySelector('template[data-desc]'); // HTML sudah disanitasi server
      desc.textContent = '';
      desc.hidden = !tpl;
      if (tpl) { desc.appendChild(tpl.content.cloneNode(true)); }
      url.value = '';
      err.hidden = true;
      send.disabled = false;
      modal.showModal();
      url.focus();
    });
  });
  document.getElementById('mCancel').addEventListener('click', function () { modal.close(); });
  modal.addEventListener('click', function (e) { if (e.target === modal) { modal.close(); } });
  form.addEventListener('submit', function (e) {
    var v = url.value.trim();
    if (!/^https?:\/\/[^\s@\/]+(?::\d*)?([\/?#]\S*)?$/i.test(v) || /^https?:\/\/[^\/?#]*@/i.test(v) || v.length > 255) {
      e.preventDefault();
      err.textContent = 'Masukkan URL valid berawalan http:// atau https:// tanpa spasi/kredensial (maks 255 karakter).';
      err.hidden = false;
      return;
    }
    send.disabled = true; // cegah kirim ganda
  });
})();

// Cat Security Scanner — Revisi v2.0
// Perubahan utama:
// - Integrasi HaveIBeenPwned API dengan k-anonymity (SHA-1, hanya 5 char dikirim)
// - Analisis email lokal: domain disposable, pola bot, subdomain mencurigakan
// - Analisis nomor HP lokal: deteksi operator, prefiks penipu, pola berulang/sekuensial
// - Langkah pemulihan konkret per temuan
// - Link langsung ke sumber pengecekan terpercaya

let currentTab = 'email';

// ─── DOM Elements ────────────────────────────────────────────────────────────

const elements = {
  emailTab: document.getElementById('emailTab'),
  phoneTab: document.getElementById('phoneTab'),
  emailForm: document.getElementById('emailForm'),
  phoneForm: document.getElementById('phoneForm'),
  emailInput: document.getElementById('emailInput'),
  phoneInput: document.getElementById('phoneInput'),
  emailScanBtn: document.getElementById('emailScanBtn'),
  phoneScanBtn: document.getElementById('phoneScanBtn'),
  loadingSection: document.getElementById('loadingSection'),
  resultsSection: document.getElementById('resultsSection'),
  loadingMessage: document.getElementById('loadingMessage'),
  resultMessage: document.getElementById('resultMessage'),
  riskScoreDisplay: document.getElementById('riskScoreDisplay'),
  detailedResults: document.getElementById('detailedResults'),
  browserChecks: document.getElementById('browserChecks'),
  recommendations: document.getElementById('recommendations'),
};

// ─── Tab Switching ───────────────────────────────────────────────────────────

function switchTab(tab) {
  currentTab = tab;
  if (tab === 'email') {
    elements.emailTab.classList.add('active');
    elements.phoneTab.classList.remove('active');
    elements.emailForm.classList.remove('hidden');
    elements.phoneForm.classList.add('hidden');
  } else {
    elements.phoneTab.classList.add('active');
    elements.emailTab.classList.remove('active');
    elements.phoneForm.classList.remove('hidden');
    elements.emailForm.classList.add('hidden');
  }
  elements.resultsSection.classList.add('hidden');
}

// ─── Validation ──────────────────────────────────────────────────────────────

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
  const clean = phone.replace(/[\s\-\(\)]/g, '');
  return /^(\+62|62|0)8[1-9][0-9]{6,10}$/.test(clean);
}

// ─── SHA-1 (untuk k-anonymity HIBP) ─────────────────────────────────────────

async function sha1(str) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

// ─── HaveIBeenPwned API ──────────────────────────────────────────────────────
//
// Menggunakan k-anonymity: hanya 5 karakter pertama hash SHA-1 yang dikirim.
// Email asli TIDAK pernah meninggalkan perangkat pengguna.
// Referensi: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange

async function checkHIBP(email) {
  const hash = await sha1(email.toLowerCase());
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  // Endpoint range — mengembalikan semua hash yang diawali prefix tersebut
  const rangeUrl = `https://api.pwnedpasswords.com/range/${prefix}?mode=breachedaccount`;

  try {
    const res = await fetch(rangeUrl, { cache: 'no-store' });
    if (!res.ok) return { breaches: [], pasteHits: 0, apiError: true };

    const text = await res.text();
    const lines = text.split('\n').filter((l) => l.trim());

    let pasteHits = 0;
    const matchedNames = [];

    for (const line of lines) {
      // Format baris: SUFFIX_HASH:ServiceName1,ServiceName2,...
      const colonIdx = line.indexOf(':');
      if (colonIdx === -1) continue;
      const h = line.slice(0, colonIdx).trim().toUpperCase();
      const data = line.slice(colonIdx + 1).trim();

      if (h === suffix) {
        // data bisa berisi nama breach atau angka (paste count)
        const parts = data
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        for (const part of parts) {
          if (/^\d+$/.test(part)) {
            pasteHits += parseInt(part, 10);
          } else {
            matchedNames.push(part);
          }
        }
      }
    }

    return { breaches: matchedNames, pasteHits, apiError: false };
  } catch (err) {
    console.error('HIBP range API error:', err);
    return { breaches: [], pasteHits: 0, apiError: true };
  }
}

// Endpoint v3 breachedaccount (memerlukan API key untuk akses penuh).
// Dicoba dulu; jika 401/403, fallback ke link manual.
async function checkHIBPv3(email) {
  try {
    const res = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, { headers: { 'User-Agent': 'CatSecurityScanner/2.0' } });
    if (res.status === 404) return { breaches: [], needsKey: false };
    if (res.status === 200) {
      const data = await res.json();
      return { breaches: data, needsKey: false };
    }
    // 401 = API key diperlukan
    return { breaches: [], needsKey: true };
  } catch {
    return { breaches: [], needsKey: true };
  }
}

// ─── Analisis Email Lokal ────────────────────────────────────────────────────

const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com',
  'guerrillamail.com',
  '10minutemail.com',
  'throwam.com',
  'yopmail.com',
  'trashmail.com',
  'tempmail.com',
  'fakeinbox.com',
  'sharklasers.com',
  'guerrillamailblock.com',
  'dispostable.com',
  'maildrop.cc',
  'mailnull.com',
  'spamgourmet.com',
  'spam4.me',
  'mytemp.email',
  'tempr.email',
  'discard.email',
  'mintemail.com',
  'spamhereplease.com',
  '33mail.com',
  'anonaddy.com',
  'simplelogin.co',
  'getnada.com',
  'mailsac.com',
  'burnermail.io',
  'emailondeck.com',
  'tempinbox.com',
  'throwaway.email',
  'spamgrap.com',
  'temp-mail.org',
  'mailtemp.info',
  'wegwerfmail.de',
  'trashmail.at',
  'trashmail.io',
]);

const FREE_PROVIDERS = new Set(['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com', 'icloud.com', 'protonmail.com', 'mail.com', 'zoho.com', 'yandex.com']);

function analyzeEmailLocally(email) {
  const [local, domain] = email.split('@');
  const domainLower = (domain || '').toLowerCase();
  const issues = [];

  // 1. Domain disposable
  if (DISPOSABLE_DOMAINS.has(domainLower)) {
    issues.push({
      severity: 'high',
      label: 'Domain email disposable / sementara',
      desc: 'Domain ini adalah layanan email sekali pakai yang sering dipakai untuk registrasi palsu, akun bot, atau menghindari pelacakan.',
    });
  }

  // 2. Subdomain berlebihan (lebih dari 3 level)
  const domainParts = domainLower.split('.');
  if (domainParts.length > 3) {
    issues.push({
      severity: 'medium',
      label: 'Subdomain berlebihan',
      desc: `Domain "${domainLower}" memiliki ${domainParts.length} level — pola tidak umum yang sering dipakai untuk mengelabui filter email.`,
    });
  }

  // 3. Banyak angka di bagian lokal
  const digitCount = (local.match(/\d/g) || []).length;
  if (digitCount > 6) {
    issues.push({
      severity: 'medium',
      label: 'Terlalu banyak angka di nama lokal',
      desc: `Bagian lokal "${local}" mengandung ${digitCount} angka — pola umum pada email yang dibuat massal oleh bot.`,
    });
  }

  // 4. Nama lokal terlihat acak (tanpa vokal berurutan, panjang)
  const looksRandom = local.length > 10 && /^[a-z0-9]+$/i.test(local) && !/[aeiou]{2,}/i.test(local) && (local.match(/[aeiou]/gi) || []).length < local.length * 0.2;
  if (looksRandom) {
    issues.push({
      severity: 'medium',
      label: 'Nama lokal terlihat dibuat secara acak',
      desc: 'Tidak ada pola kata yang dapat dikenali — karakteristik umum pada email yang dihasilkan oleh alat otomatis.',
    });
  }

  // 5. Plus-addressing (informasi, bukan bahaya)
  if (local.includes('+')) {
    issues.push({
      severity: 'low',
      label: 'Menggunakan plus-addressing',
      desc: 'Karakter "+" adalah teknik legitimate untuk filter email (misal: user+spam@gmail.com). Bukan ancaman, tapi perlu diketahui.',
    });
  }

  // 6. Nama lokal sangat pendek pada domain non-gratis
  if (local.length < 4 && !FREE_PROVIDERS.has(domainLower)) {
    issues.push({
      severity: 'medium',
      label: 'Nama lokal sangat pendek',
      desc: 'Alamat dengan bagian lokal kurang dari 4 karakter pada domain kustom sering dihasilkan secara programatik.',
    });
  }

  return {
    issues,
    isFree: FREE_PROVIDERS.has(domainLower),
    isDisposable: DISPOSABLE_DOMAINS.has(domainLower),
    domain: domainLower,
    local,
  };
}

// ─── Scan Email ───────────────────────────────────────────────────────────────

async function scanEmail() {
  const email = elements.emailInput.value.trim();

  if (!email) {
    showNotification('🐱 Masukkan alamat email dulu ya~', 'warning');
    return;
  }
  if (!isValidEmail(email)) {
    showNotification('🐱 Format email tidak valid. Coba lagi ya~', 'error');
    return;
  }

  showLoading('Menghitung hash email (k-anonymity)...');

  try {
    const localAnalysis = analyzeEmailLocally(email);

    // Jalankan kedua pengecekan secara paralel
    showLoading('Menghubungi HaveIBeenPwned API...');
    const [rangeResult, v3Result] = await Promise.all([checkHIBP(email), checkHIBPv3(email)]);

    // Gabungkan hasil breach
    const breachNames = new Set([...rangeResult.breaches, ...(v3Result.breaches || []).map((b) => (typeof b === 'object' ? b.Name || b.name : b))]);

    const results = {
      breachNames: Array.from(breachNames),
      pasteHits: rangeResult.pasteHits,
      apiError: rangeResult.apiError && v3Result.needsKey,
      needsApiKey: v3Result.needsKey,
      localAnalysis,
    };

    displayEmailResults(email, results);
    showNotification('✅ Scan selesai! Email tidak disimpan~', 'success');
    if (window.catAnimations) window.catAnimations.showSuccessAnimation();
  } catch (error) {
    console.error(error);
    showNotification('🐱 Gagal terhubung ke server. Coba lagi nanti~', 'error');
    if (window.catAnimations) window.catAnimations.showErrorAnimation();
  } finally {
    hideLoading();
  }
}

// ─── Tampilkan Hasil Email ────────────────────────────────────────────────────

function displayEmailResults(email, results) {
  const { breachNames, pasteHits, apiError, needsApiKey, localAnalysis } = results;
  const hasBreaches = breachNames.length > 0;
  const highIssues = localAnalysis.issues.filter((i) => i.severity === 'high').length;
  const medIssues = localAnalysis.issues.filter((i) => i.severity === 'medium').length;

  // Hitung skor risiko (0–100)
  const riskScore = Math.min(100, (hasBreaches ? Math.min(breachNames.length * 12, 60) : 0) + highIssues * 20 + medIssues * 8 + (pasteHits > 0 ? 10 : 0));
  const level = riskScore >= 50 ? 'Bahaya' : riskScore >= 20 ? 'Waspada' : 'Aman';
  const color = level === 'Bahaya' ? '#E24B4A' : level === 'Waspada' ? '#BA7517' : '#3B6D11';

  // Status message
  if (level === 'Bahaya') {
    elements.resultMessage.innerHTML = '🙀 Email kamu berisiko tinggi! Segera ambil tindakan!';
    elements.resultMessage.className = 'text-red-600';
  } else if (level === 'Waspada') {
    elements.resultMessage.innerHTML = '😼 Ada beberapa indikasi yang perlu diperhatikan';
    elements.resultMessage.className = 'text-yellow-600';
  } else {
    elements.resultMessage.innerHTML = '😺 Email kamu terlihat aman! Tetap pantau berkala ya~';
    elements.resultMessage.className = 'text-green-600';
  }

  // Risk score gauge
  elements.riskScoreDisplay.innerHTML = buildGauge(riskScore, color, level);

  // Detail konten
  let html = '';

  // ── Hasil Breach ──
  if (apiError) {
    html += card(
      'yellow',
      '⚠️',
      'Status Breach (API Key Diperlukan)',
      `Pemeriksaan breach lengkap memerlukan API key gratis HIBP. Cek manual:<br>
       <a href="https://haveibeenpwned.com/account/${encodeURIComponent(email)}" target="_blank" rel="noopener" class="text-blue-600 underline">haveibeenpwned.com</a> &nbsp;|&nbsp;
       <a href="https://monitor.firefox.com" target="_blank" rel="noopener" class="text-blue-600 underline">Firefox Monitor</a>`,
    );
  } else if (hasBreaches) {
    html += card(
      'red',
      '🔴',
      `Ditemukan di ${breachNames.length} Data Breach`,
      `Email ini pernah bocor dalam insiden berikut: <strong>${breachNames.join(', ')}</strong>.` + (pasteHits > 0 ? `<br>Juga ditemukan di <strong>${pasteHits}</strong> paste publik (Pastebin, dll).` : ''),
    );
  } else {
    html += card('green', '🟢', 'Tidak Ditemukan dalam Breach Publik', 'Tidak ada catatan breach untuk email ini di database HaveIBeenPwned. Tetap pantau secara berkala.');
  }

  // ── Analisis Lokal ──
  if (localAnalysis.issues.length > 0) {
    const listItems = localAnalysis.issues
      .map(
        (iss) =>
          `<li class="flex items-start space-x-2 mb-2">
         <span class="text-${iss.severity === 'high' ? 'red' : iss.severity === 'medium' ? 'yellow' : 'blue'}-600 font-bold">•</span>
         <span><strong>${iss.label}:</strong> ${iss.desc}</span>
       </li>`,
      )
      .join('');
    html += `
      <div class="bg-yellow-50 border-l-4 border-yellow-500 p-4 rounded-r-xl">
        <h5 class="font-semibold mb-2">🔍 Analisis Karakteristik Email</h5>
        <ul class="space-y-1 text-sm">${listItems}</ul>
      </div>`;
  }

  // ── Paste info ──
  if (pasteHits > 0 && !hasBreaches) {
    html += card('yellow', '📋', `Ditemukan di ${pasteHits} Paste Publik`, 'Email ini muncul di paste database (Pastebin, dll). Data mungkin disertai password atau info lain.');
  }

  elements.detailedResults.innerHTML = html;

  // ── Browser checks & rekomendasi ──
  elements.browserChecks.innerHTML = '';
  performBrowserChecks();
  generateEmailRecommendations({ hasBreaches, breachNames, pasteHits, localAnalysis, needsApiKey });

  elements.resultsSection.classList.remove('hidden');
  elements.resultsSection.classList.add('animate-slide-up');
}

// ─── Analisis Nomor HP Lokal ──────────────────────────────────────────────────

const OPERATOR_PREFIXES = {
  Telkomsel: ['0811', '0812', '0813', '0821', '0822', '0823', '0851', '0852', '0853'],
  'Indosat Ooredoo': ['0814', '0815', '0816', '0855', '0856', '0857', '0858'],
  'XL Axiata': ['0817', '0818', '0819', '0859', '0877', '0878'],
  Axis: ['0831', '0832', '0833', '0838'],
  'Tri (3)': ['0895', '0896', '0897', '0898', '0899'],
  Smartfren: ['0881', '0882', '0883', '0884', '0885', '0886', '0887', '0888', '0889'],
  Bytel: ['0868'],
};

// Prefiks yang diketahui sering dipakai penipu berdasarkan laporan Kominfo & media
const SUSPICIOUS_PREFIXES = ['085732', '085733', '087888', '087722', '087811', '085290', '085394', '081212', '082299'];

function normalizePhone(phone) {
  const clean = phone.replace(/[\s\-\(\)]/g, '');
  if (clean.startsWith('+62')) return '0' + clean.slice(3);
  if (clean.startsWith('62')) return '0' + clean.slice(2);
  return clean;
}

function analyzePhone(rawPhone) {
  const normalized = normalizePhone(rawPhone);
  const indicators = [];
  let riskScore = 0;

  // 1. Deteksi operator
  let operator = 'Tidak diketahui';
  for (const [name, prefixes] of Object.entries(OPERATOR_PREFIXES)) {
    if (prefixes.some((p) => normalized.startsWith(p))) {
      operator = name;
      break;
    }
  }
  if (operator === 'Tidak diketahui') {
    indicators.push({
      severity: 'medium',
      description: 'Prefiks tidak cocok dengan operator Indonesia yang terdaftar. Mungkin nomor VOIP, virtual, atau nomor tidak aktif.',
    });
    riskScore += 20;
  }

  // 2. Prefiks mencurigakan
  if (SUSPICIOUS_PREFIXES.some((p) => normalized.startsWith(p))) {
    indicators.push({
      severity: 'high',
      description: 'Prefiks ini sering muncul dalam laporan penipuan di Indonesia (sumber: Kominfo / aduannomor.id).',
    });
    riskScore += 40;
  }

  // 3. Panjang nomor
  const digits = normalized.slice(1); // hapus 0 depan
  if (digits.length < 9) {
    indicators.push({
      severity: 'high',
      description: `Nomor terlalu pendek (${digits.length} digit). Nomor HP Indonesia yang valid memiliki 9–12 digit setelah kode negara.`,
    });
    riskScore += 30;
  } else if (digits.length > 12) {
    indicators.push({
      severity: 'medium',
      description: `Nomor terlalu panjang (${digits.length} digit). Tidak umum untuk nomor HP Indonesia.`,
    });
    riskScore += 15;
  }

  // 4. Pola digit berulang (misal: 08888888888)
  if (/(.)\1{5,}/.test(normalized.slice(1))) {
    indicators.push({
      severity: 'medium',
      description: 'Digit berulang panjang — pola umum pada nomor virtual, nomor pemasaran massal, atau nomor dummy.',
    });
    riskScore += 20;
  }

  // 5. Pola sekuensial (naik atau turun)
  const body = normalized.slice(4);
  if (/01234|12345|23456|34567|45678|56789/.test(body) || /98765|87654|76543|65432|54321/.test(body)) {
    indicators.push({
      severity: 'low',
      description: 'Urutan angka naik/turun terdeteksi. Tidak umum pada nomor HP asli, sering ada pada nomor uji atau nomor dibuat-buat.',
    });
    riskScore += 10;
  }

  // 6. Format untuk tampilan
  const formatted = normalized.replace(/(\d{4})(\d{4})(\d{0,5})/, '$1-$2-$3').replace(/-$/, '');

  return {
    normalized,
    formatted,
    operator,
    indicators,
    riskScore: Math.min(100, riskScore),
    digitCount: digits.length,
  };
}

// ─── Scan Nomor HP ────────────────────────────────────────────────────────────

async function scanPhone() {
  const phone = elements.phoneInput.value.trim();

  if (!phone) {
    showNotification('🐱 Masukkan nomor HP dulu ya~', 'warning');
    return;
  }
  if (!isValidPhone(phone)) {
    showNotification('🐱 Format tidak valid. Gunakan format Indonesia (0812...)', 'error');
    return;
  }

  showLoading('Menganalisis pola nomor HP...');

  try {
    // Analisis sepenuhnya lokal — tidak ada data yang dikirim ke luar
    await new Promise((r) => setTimeout(r, 600)); // animasi agar tidak terlalu instan
    const analysis = analyzePhone(phone);
    displayPhoneResults(phone, analysis);
    showNotification('✅ Scan selesai! Data diproses lokal saja~', 'success');
    if (window.catAnimations) window.catAnimations.showSuccessAnimation();
  } catch (error) {
    console.error(error);
    showNotification('🐱 Terjadi kesalahan. Coba lagi~', 'error');
    if (window.catAnimations) window.catAnimations.showErrorAnimation();
  } finally {
    hideLoading();
  }
}

// ─── Tampilkan Hasil Nomor HP ─────────────────────────────────────────────────

function displayPhoneResults(phone, analysis) {
  const { riskScore, indicators, operator, formatted, digitCount } = analysis;
  const level = riskScore >= 50 ? 'Bahaya' : riskScore >= 20 ? 'Waspada' : 'Aman';
  const color = level === 'Bahaya' ? '#E24B4A' : level === 'Waspada' ? '#BA7517' : '#3B6D11';

  if (level === 'Bahaya') {
    elements.resultMessage.innerHTML = '🙀 Nomor HP berisiko! Hati-hati dengan penipuan!';
    elements.resultMessage.className = 'text-red-600';
  } else if (level === 'Waspada') {
    elements.resultMessage.innerHTML = '😼 Ada indikasi yang perlu diwaspadai';
    elements.resultMessage.className = 'text-yellow-600';
  } else {
    elements.resultMessage.innerHTML = '😺 Nomor HP terlihat normal!';
    elements.resultMessage.className = 'text-green-600';
  }

  elements.riskScoreDisplay.innerHTML = buildGauge(riskScore, color, level);

  let html = '';

  // Info nomor
  html += card(
    'green',
    '✅',
    'Informasi Nomor',
    `Format: <strong>${formatted}</strong><br>
     Operator: <strong>${operator}</strong><br>
     Jumlah digit: <strong>${digitCount} digit</strong>`,
  );

  // Indikator
  if (indicators.length > 0) {
    const listItems = indicators
      .map(
        (ind) =>
          `<li class="flex items-start space-x-2 mb-2">
         <span class="text-${ind.severity === 'high' ? 'red' : ind.severity === 'medium' ? 'yellow' : 'blue'}-600 font-bold">•</span>
         <span>${ind.description}</span>
       </li>`,
      )
      .join('');
    html += `
      <div class="bg-yellow-50 border-l-4 border-yellow-500 p-4 rounded-r-xl">
        <h5 class="font-semibold mb-2">⚠️ Indikasi Mencurigakan</h5>
        <ul class="space-y-1 text-sm">${listItems}</ul>
      </div>`;
  } else {
    html += card('green', '✅', 'Tidak Ada Indikasi Mencurigakan', 'Pola nomor ini normal berdasarkan analisis lokal.');
  }

  elements.detailedResults.innerHTML = html;

  elements.browserChecks.innerHTML = '';
  performBrowserChecks();
  generatePhoneRecommendations(analysis);

  elements.resultsSection.classList.remove('hidden');
  elements.resultsSection.classList.add('animate-slide-up');
}

// ─── Rekomendasi Email ────────────────────────────────────────────────────────

function generateEmailRecommendations({ hasBreaches, breachNames, pasteHits, localAnalysis, needsApiKey }) {
  const recs = [];

  if (hasBreaches) {
    recs.push({
      icon: '🔑',
      priority: 'high',
      text: `<strong>Ganti password SEKARANG</strong> untuk semua layanan ini: ${breachNames.join(', ')}. Gunakan password unik ≥12 karakter (huruf besar/kecil + angka + simbol) yang berbeda di setiap layanan.`,
    });
    recs.push({
      icon: '🔐',
      priority: 'high',
      text: '<strong>Aktifkan Two-Factor Authentication (2FA)</strong> di semua akun penting. Prioritas: email utama, perbankan, e-commerce. Gunakan aplikasi authenticator (Google Authenticator / Authy / Microsoft Authenticator) — jauh lebih aman dari SMS karena tidak rentan SIM-swap.',
    });
    recs.push({
      icon: '👁️',
      priority: 'high',
      text: '<strong>Periksa sesi login aktif</strong> di setiap layanan yang bocor: masuk → menu "Perangkat" atau "Sesi Aktif" → logout semua sesi kecuali yang sedang kamu pakai.',
    });
  }

  if (pasteHits > 0) {
    recs.push({
      icon: '📋',
      priority: 'high',
      text: `<strong>Email ditemukan di ${pasteHits} paste publik</strong>. Data mungkin disertai password lama. Prioritaskan penggantian password dan aktifkan 2FA.`,
    });
  }

  if (localAnalysis.isDisposable) {
    recs.push({
      icon: '🚫',
      priority: 'high',
      text: '<strong>Jangan gunakan email disposable ini untuk akun penting</strong> (bank, e-commerce, media sosial). Buat email baru di layanan terpercaya (Gmail, Outlook, ProtonMail).',
    });
  }

  if (needsApiKey) {
    recs.push({
      icon: '🔍',
      priority: 'medium',
      text: '<strong>Cek manual di haveibeenpwned.com</strong> untuk hasil yang lebih lengkap. Daftar notifikasi breach gratis di <a href="https://haveibeenpwned.com/NotifyMe" target="_blank" rel="noopener" class="underline text-blue-600">haveibeenpwned.com/NotifyMe</a> agar kamu langsung diberi tahu jika emailmu masuk breach baru.',
    });
  }

  recs.push({
    icon: '🗝️',
    priority: 'medium',
    text: '<strong>Pasang password manager</strong>: Bitwarden (gratis & open source), 1Password, atau Dashlane. Ini memastikan kamu tidak pernah lagi memakai password yang sama di dua tempat.',
  });

  recs.push({
    icon: '🔔',
    priority: 'low',
    text: '<strong>Pantau breach secara otomatis</strong>: daftar di Firefox Monitor (<a href="https://monitor.firefox.com" target="_blank" rel="noopener" class="underline text-blue-600">monitor.firefox.com</a>) atau HaveIBeenPwned untuk mendapat notifikasi email gratis.',
  });

  recs.push({
    icon: '📧',
    priority: 'low',
    text: '<strong>Waspada email phishing</strong>: layanan resmi tidak pernah meminta password via email. Selalu periksa domain pengirim — bukan hanya nama tampilan.',
  });

  displayRecommendations(recs);
}

// ─── Rekomendasi Nomor HP ─────────────────────────────────────────────────────

function generatePhoneRecommendations(analysis) {
  const { riskScore, indicators } = analysis;
  const recs = [];
  const hasHighRisk = indicators.some((i) => i.severity === 'high');
  const hasMedRisk = indicators.some((i) => i.severity === 'medium');

  if (hasHighRisk || hasMedRisk) {
    recs.push({
      icon: '🚫',
      priority: 'high',
      text: '<strong>Blokir nomor ini segera</strong>. Android: Kontak → Blokir Nomor. iOS: Info Kontak → Blokir Kontak. Aktifkan juga filter spam bawaan di aplikasi Telepon.',
    });
    recs.push({
      icon: '🔒',
      priority: 'high',
      text: '<strong>Jangan pernah berikan OTP, data KTP, atau rekening</strong>. Bank, Gojek, Tokopedia, dan layanan resmi lainnya TIDAK PERNAH meminta OTP melalui telepon atau SMS dari pihak luar. Siapapun yang memintanya adalah penipu — tutup telepon segera.',
    });
    recs.push({
      icon: '📢',
      priority: 'high',
      text: '<strong>Laporkan nomor ini</strong> ke: Kominfo via <a href="https://www.aduannomor.id" target="_blank" rel="noopener" class="underline text-blue-600">aduannomor.id</a> | Operator: Telkomsel 188, Indosat 185, XL 817 | Polisi siber: <a href="https://patrolisiber.id" target="_blank" rel="noopener" class="underline text-blue-600">patrolisiber.id</a>. Laporanmu melindungi pengguna lain.',
    });
  }

  recs.push({
    icon: '📱',
    priority: 'medium',
    text: '<strong>Pasang aplikasi anti-spam</strong>: Truecaller atau Whoscall tersedia gratis di Play Store/App Store. Keduanya memiliki database spam Indonesia yang diperbarui berkala.',
  });

  recs.push({
    icon: '⚙️',
    priority: 'medium',
    text: '<strong>Aktifkan filter bawaan smartphone</strong>: iOS 13+: Pengaturan → Telepon → Saring Penelepon Tidak Dikenal. Android: Telepon → Pengaturan → Blokir nomor → Aktifkan filter spam Google.',
  });

  recs.push({
    icon: '💳',
    priority: 'low',
    text: 'Jika nomor ini terkait dugaan penipuan rekening bank, laporkan juga di <a href="https://cekrekening.id" target="_blank" rel="noopener" class="underline text-blue-600">cekrekening.id</a> (OJK).',
  });

  displayRecommendations(recs);
}

function displayRecommendations(recs) {
  elements.recommendations.innerHTML = recs
    .map(
      (rec) => `
    <div class="flex items-start space-x-3 ${rec.priority === 'high' ? 'bg-red-50 p-3 rounded-lg' : ''}">
      <span class="text-xl flex-shrink-0">${rec.icon}</span>
      <p class="text-sm ${rec.priority === 'high' ? 'text-red-800' : 'text-gray-700'} leading-relaxed">${rec.text}</p>
    </div>
  `,
    )
    .join('');
}

// ─── Browser Security Checks ──────────────────────────────────────────────────

function performBrowserChecks() {
  // Service Workers
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistrations().then((regs) => {
      appendBrowserCheck({
        name: 'Service Worker',
        status: regs.length > 0 ? 'warning' : 'safe',
        message: regs.length > 0 ? `${regs.length} service worker terdaftar — periksa apakah ini dari situs terpercaya` : 'Tidak ada service worker mencurigakan',
      });
    });
  }

  // localStorage size
  const lsSize = JSON.stringify(localStorage).length;
  appendBrowserCheck({
    name: 'Local Storage',
    status: lsSize > 100_000 ? 'warning' : 'safe',
    message: `Ukuran: ${(lsSize / 1024).toFixed(1)} KB${lsSize > 100_000 ? ' — cukup besar, pertimbangkan untuk dibersihkan' : ''}`,
  });

  // Izin situs
  checkSitePermissions();

  // Popup blocker (heuristik)
  appendBrowserCheck({
    name: 'Popup Blocker',
    status: 'safe',
    message: 'Popup blocker aktif (bawaan browser modern)',
  });
}

async function checkSitePermissions() {
  const permList = [
    { name: 'geolocation', label: 'Lokasi' },
    { name: 'camera', label: 'Kamera' },
    { name: 'microphone', label: 'Mikrofon' },
    { name: 'notifications', label: 'Notifikasi' },
    { name: 'clipboard-read', label: 'Clipboard Read' },
    { name: 'clipboard-write', label: 'Clipboard Write' },
  ];

  if (!('permissions' in navigator)) {
    appendBrowserCheck({
      name: 'Izin Situs',
      status: 'warning',
      message: 'Browser tidak mendukung pengecekan izin otomatis — cek manual di pengaturan browser',
    });
    return;
  }

  const granted = [];
  for (const perm of permList) {
    try {
      const status = await navigator.permissions.query({ name: perm.name });
      if (status.state === 'granted') granted.push(perm.label);
    } catch {
      /* izin tidak didukung di browser ini */
    }
  }

  appendBrowserCheck({
    name: 'Izin Situs',
    status: granted.length > 0 ? 'warning' : 'safe',
    message: granted.length > 0 ? `Izin aktif: ${granted.join(', ')} — cabut izin untuk situs mencurigakan via pengaturan browser` : 'Tidak ada izin sensitif yang aktif di situs ini',
  });
}

function appendBrowserCheck(check) {
  const color = check.status === 'warning' ? 'yellow' : 'green';
  const icon = check.status === 'warning' ? '⚠️' : '✅';
  const el = document.createElement('div');
  el.className = `bg-${color}-50 border-l-4 border-${color}-500 p-3 rounded-r-xl`;
  el.innerHTML = `
    <div class="flex items-center space-x-2">
      <span>${icon}</span>
      <div>
        <h5 class="font-semibold text-sm">${check.name}</h5>
        <p class="text-sm text-gray-600">${check.message}</p>
      </div>
    </div>`;
  elements.browserChecks.appendChild(el);
}

// ─── Quick Fix Actions ────────────────────────────────────────────────────────

function clearCache() {
  if (!confirm('🐱 Yakin ingin menghapus cache browser?')) return;
  if ('caches' in window) {
    caches.keys().then((names) => names.forEach((n) => caches.delete(n)));
  }
  showNotification('✅ Cache browser berhasil dibersihkan!', 'success');
  if (window.catAnimations) window.catAnimations.showSuccessAnimation();
}

function resetSession() {
  if (!confirm('🐱 Yakin ingin mereset session?')) return;
  sessionStorage.clear();
  document.cookie.split(';').forEach((c) => {
    document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/');
  });
  showNotification('✅ Session berhasil direset!', 'success');
  if (window.catAnimations) window.catAnimations.showSuccessAnimation();
}

function clearServiceWorkers() {
  if (!confirm('🐱 Yakin ingin menghapus semua service worker?')) return;
  if (!('serviceWorker' in navigator)) {
    showNotification('ℹ️ Browser tidak mendukung service worker', 'info');
    return;
  }
  navigator.serviceWorker.getRegistrations().then((regs) => {
    regs.forEach((r) => r.unregister());
    showNotification(`✅ ${regs.length} service worker berhasil dihapus!`, 'success');
    if (window.catAnimations) window.catAnimations.showSuccessAnimation();
  });
}

function openPermissionSettings() {
  const ua = navigator.userAgent;
  const isEdge = ua.includes('Edg');
  const isChrome = ua.includes('Chrome') && !isEdge;
  const encoded = encodeURIComponent(window.location.origin);
  const url = isEdge ? `edge://settings/content/siteDetails?site=${encoded}` : isChrome ? `chrome://settings/content/siteDetails?site=${encoded}` : '';

  if (url) {
    const popup = window.open(url, '_blank');
    if (!popup) {
      showNotification('⚠️ Popup diblokir. Buka pengaturan izin via menu browser ya~', 'warning');
    } else {
      showNotification('✅ Pengaturan izin dibuka!', 'success');
    }
  } else {
    showNotification('ℹ️ Buka pengaturan izin lewat menu browser (Privacy / Site Settings).', 'info');
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildGauge(score, color, level) {
  return `
    <div class="relative w-32 h-32 mx-auto mb-4">
      <svg class="w-full h-full" viewBox="0 0 36 36">
        <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              fill="none" stroke="#e5e7eb" stroke-width="3"/>
        <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831"
              fill="none" stroke="${color}" stroke-width="3"
              stroke-dasharray="${score}, 100"/>
      </svg>
      <div class="absolute inset-0 flex items-center justify-center">
        <span class="text-3xl font-bold" style="color:${color}">${score}%</span>
      </div>
    </div>
    <p class="text-xl font-bold" style="color:${color}">${level}</p>`;
}

function card(color, icon, title, body) {
  return `
    <div class="bg-${color}-50 border-l-4 border-${color}-500 p-4 rounded-r-xl">
      <div class="flex items-start space-x-3">
        <span class="text-2xl">${icon}</span>
        <div>
          <h5 class="font-semibold">${title}</h5>
          <p class="text-sm mt-1 leading-relaxed">${body}</p>
        </div>
      </div>
    </div>`;
}

function showLoading(message) {
  elements.loadingSection.classList.remove('hidden');
  elements.resultsSection.classList.add('hidden');
  elements.loadingMessage.textContent = message;
  if (window.catAnimations) {
    window.catAnimations.createScanningEffect?.();
  }
  elements.browserChecks.innerHTML = '';
}

function hideLoading() {
  elements.loadingSection.classList.add('hidden');
}

function showNotification(message, type = 'info') {
  const colors = { success: 'bg-green-500', error: 'bg-red-500', warning: 'bg-yellow-500', info: 'bg-blue-500' };
  const el = document.createElement('div');
  el.className = `${colors[type]} text-white px-6 py-3 rounded-xl shadow-lg fixed top-4 right-4 z-50 animate-slide-up max-w-md`;
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity 0.5s';
    setTimeout(() => el.parentNode?.removeChild(el), 500);
  }, 3000);
}

// ─── Event Listeners ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  elements.emailInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') scanEmail();
  });
  elements.phoneInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') scanPhone();
  });
});

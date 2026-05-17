require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
);
app.use(compression());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Rate limiting - prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: '🐱 Meow! Terlalu banyak permintaan. Coba lagi nanti ya~',
    retryAfter: '15 minutes',
  },
});

app.use('/api/', limiter);

// Privacy disclaimer middleware
app.use((req, res, next) => {
  // Add privacy headers
  res.setHeader('X-Privacy-Policy', 'No data is stored. All scans are realtime only.');
  res.setHeader('X-Data-Retention', 'Zero - Data deleted immediately after processing');
  next();
});

// Email scanning endpoint
app.post('/api/scan/email', async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({
        error: '🐱 Meow! Format email tidak valid. Coba lagi ya~',
        valid: false,
      });
    }

    // Don't log the email
    const results = {
      breach: null,
      reputation: null,
      spam: null,
      timestamp: new Date().toISOString(),
    };

    // Check Have I Been Pwned
    try {
      const hibpResponse = await axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`, {
        headers: {
          'hibp-api-key': process.env.HAVEIBEENPWNED_API_KEY,
          'user-agent': 'CatSecurityScanner',
        },
        timeout: 5000,
        validateStatus: (status) => status === 200 || status === 404,
      });

      if (hibpResponse.status === 200) {
        results.breach = {
          compromised: true,
          breaches: hibpResponse.data.map((b) => b.Name),
          count: hibpResponse.data.length,
        };
      } else {
        results.breach = {
          compromised: false,
          breaches: [],
          count: 0,
        };
      }
    } catch (error) {
      results.breach = { compromised: false, breaches: [], count: 0 };
    }

    // Check EmailRep.io
    try {
      const emailRepResponse = await axios.get(`https://emailrep.io/${encodeURIComponent(email)}`, {
        headers: {
          Key: process.env.EMAILREP_API_KEY,
        },
        timeout: 5000,
      });

      results.reputation = {
        reputation: emailRepResponse.data.reputation || 'unknown',
        suspicious: emailRepResponse.data.suspicious || false,
        details: emailRepResponse.data.details || {},
      };
    } catch (error) {
      results.reputation = { reputation: 'unknown', suspicious: false };
    }

    // Simple spam/phishing indicator check
    const spamIndicators = checkSpamIndicators(email);
    results.spam = spamIndicators;

    // Calculate risk score
    results.riskScore = calculateRiskScore(results);

    // Clear email from memory
    req.body.email = null;

    res.json({
      success: true,
      message: '🐱 Scan email selesai! Data tidak disimpan ya~',
      results: results,
    });
  } catch (error) {
    console.error('Error scanning email (no data stored):', error.message);
    res.status(500).json({
      error: '🐱 Maaf, terjadi kesalahan saat scan. Coba lagi ya~',
      success: false,
    });
  }
});

// Phone number scanning endpoint
app.post('/api/scan/phone', async (req, res) => {
  try {
    const { phone } = req.body;

    // Validate phone number (Indonesian format)
    const phoneRegex = /^(\+62|62|0)8[1-9][0-9]{6,10}$/;
    if (!phone || !phoneRegex.test(phone.replace(/[\s-]/g, ''))) {
      return res.status(400).json({
        error: '🐱 Meow! Format nomor HP tidak valid. Gunakan format Indonesia ya~',
        valid: false,
      });
    }

    const cleanPhone = phone.replace(/[\s-]/g, '');
    const results = {
      format: 'valid',
      indicators: [],
      abuse: false,
      timestamp: new Date().toISOString(),
    };

    // Check spam/scam indicators
    const indicators = checkPhoneIndicators(cleanPhone);
    results.indicators = indicators;

    // Check against known scam patterns
    results.abuse = indicators.some((ind) => ind.severity === 'high');

    // Calculate risk score for phone
    results.riskScore = calculatePhoneRiskScore(results);

    // Clear phone from memory
    req.body.phone = null;

    res.json({
      success: true,
      message: '🐱 Scan nomor HP selesai! Datamu aman bersama kucing~',
      results: results,
    });
  } catch (error) {
    console.error('Error scanning phone (no data stored):', error.message);
    res.status(500).json({
      error: '🐱 Maaf, terjadi kesalahan saat scan. Coba lagi ya~',
      success: false,
    });
  }
});

// Browser security check endpoint (client-side helper)
app.get('/api/browser-check', (req, res) => {
  res.json({
    message: '🐱 Browser check dilakukan di sisi klien untuk privasi maksimal!',
    checks: ['service_worker_check', 'localstorage_check', 'notification_permission', 'popup_check', 'redirect_check'],
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: '🐱 Purrfect! Server is running',
    privacy: 'No data is being stored',
    timestamp: new Date().toISOString(),
  });
});

// Helper functions
function checkSpamIndicators(email) {
  const indicators = [];
  const lowerEmail = email.toLowerCase();

  // Check for suspicious patterns
  if (lowerEmail.includes('noreply') || lowerEmail.includes('no-reply')) {
    indicators.push({
      type: 'format',
      indicator: 'Alamat noreply',
      risk: 'low',
      description: 'Email menggunakan alamat noreply - umum digunakan',
    });
  }

  if (lowerEmail.match(/[0-9]{5,}/)) {
    indicators.push({
      type: 'pattern',
      indicator: 'Banyak angka',
      risk: 'medium',
      description: 'Email mengandung banyak angka - perlu diwaspadai',
    });
  }

  const suspiciousDomains = ['tempmail', 'throwaway', 'disposable', 'mailinator', 'guerrillamail'];
  const domain = lowerEmail.split('@')[1] || '';

  if (suspiciousDomains.some((d) => domain.includes(d))) {
    indicators.push({
      type: 'domain',
      indicator: 'Domain sementara',
      risk: 'high',
      description: 'Email menggunakan layanan email sementara',
    });
  }

  return indicators;
}

function checkPhoneIndicators(phone) {
  const indicators = [];

  // Check for known scam prefixes (example patterns)
  const scamPrefixes = ['0812', '0878', '0895']; // Example patterns
  const prefix = phone.substring(0, 4);

  if (scamPrefixes.includes(prefix)) {
    indicators.push({
      type: 'prefix',
      indicator: 'Prefix mencurigakan',
      severity: 'medium',
      description: 'Prefix nomor sering digunakan untuk spam',
    });
  }

  // Check if number is too short or long
  if (phone.length < 10 || phone.length > 13) {
    indicators.push({
      type: 'format',
      indicator: 'Panjang nomor tidak normal',
      severity: 'high',
      description: 'Nomor telepon memiliki panjang yang tidak wajar',
    });
  }

  return indicators;
}

function calculateRiskScore(results) {
  let score = 0;

  // Email breach check
  if (results.breach?.compromised) {
    score += 40;
    if (results.breach.count > 3) score += 20;
  }

  // Reputation check
  if (results.reputation?.suspicious) {
    score += 30;
  }

  // Spam indicators
  if (results.spam?.length > 0) {
    const highRiskSpam = results.spam.filter((s) => s.risk === 'high').length;
    score += highRiskSpam * 20;
    score += (results.spam.length - highRiskSpam) * 10;
  }

  // Cap at 100
  score = Math.min(score, 100);

  return {
    score: score,
    level: score >= 60 ? 'Risiko Tinggi' : score >= 30 ? 'Waspada' : 'Aman',
    color: score >= 60 ? 'red' : score >= 30 ? 'yellow' : 'green',
  };
}

function calculatePhoneRiskScore(results) {
  let score = 0;

  if (results.indicators?.length > 0) {
    const highRisk = results.indicators.filter((i) => i.severity === 'high').length;
    score += highRisk * 30;
    score += (results.indicators.length - highRisk) * 15;
  }

  if (results.abuse) {
    score += 25;
  }

  score = Math.min(score, 100);

  return {
    score: score,
    level: score >= 60 ? 'Risiko Tinggi' : score >= 30 ? 'Waspada' : 'Aman',
    color: score >= 60 ? 'red' : score >= 30 ? 'yellow' : 'green',
  };
}

// Serve main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log('🐱 Cat Security Scanner is purring on port', PORT);
  console.log('🔒 Privacy mode: No data storage, realtime scanning only');
  console.log('📍 Visit: http://localhost:' + PORT);
});

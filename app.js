import { LinkAnalyzer } from './core/link_analyzer.js';
import { QRGuardian } from './core/qr_guardian.js';
import { PaymentVerifier } from './core/payment_verifier.js';
import { ExplainabilityEngine } from './core/explainability.js';
import { ELAMagnifier } from './core/ela_magnifier.js';
import { CertificateGenerator } from './core/certificate_generator.js';

document.addEventListener('DOMContentLoaded', () => {
  // Sidebar Navigation
  const navItems = document.querySelectorAll('.nav-item');
  const modules = document.querySelectorAll('.dashboard-module');

  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      navItems.forEach(i => i.classList.remove('active'));
      modules.forEach(m => m.classList.remove('active'));

      item.classList.add('active');
      const targetId = item.getAttribute('data-target');
      document.getElementById(targetId).classList.add('active');
    });
  });

  // Modal setup for Evidence Certificate
  let modalOverlay = document.getElementById('cert-modal-overlay');
  if (!modalOverlay) {
    modalOverlay = document.createElement('div');
    modalOverlay.id = 'cert-modal-overlay';
    document.body.appendChild(modalOverlay);
  }

  function closeCertificateModal() {
    modalOverlay.classList.remove('open');
  }

  modalOverlay.addEventListener('click', (e) => {
    if (e.target === modalOverlay) closeCertificateModal();
  });

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' || e.code === 'Escape') {
      closeCertificateModal();
    }
  });

  function openCertificateModal(report) {
    const certHTML = CertificateGenerator.generateCertificateHTML 
      ? CertificateGenerator.generateCertificateHTML(report)
      : (window.CertGen ? window.CertGen.generate(report) : '');
      
    modalOverlay.innerHTML = `
      <div class="cert-modal-inner" style="position: relative; max-width: 760px; width: 100%;">
        <button id="close-cert-btn" class="cert-close-btn">✕</button>
        ${certHTML}
      </div>
    `;
    modalOverlay.offsetHeight; // Force reflow
    modalOverlay.classList.add('open');

    const closeBtn = document.getElementById('close-cert-btn');
    if (closeBtn) closeBtn.addEventListener('click', closeCertificateModal);
  }

  // MODULE 1: Link & Redirect X-Ray Scan
  const mainUrlInput = document.getElementById('main-url-input');
  const mainScanBtn = document.getElementById('main-scan-btn');
  const linkResultsContent = document.getElementById('link-results-content');

  const executeMainLinkAnalysis = async (url) => {
    linkResultsContent.innerHTML = `
      <div class="results-placeholder">
        <span class="placeholder-icon">⏳</span>
        <p>Executing Tier 1 Pre-Scan & Tier 2 Safe Hop-by-Hop Redirect X-Ray...</p>
      </div>
    `;
    const report = await LinkAnalyzer.analyzeUrl(url);
    linkResultsContent.innerHTML = ExplainabilityEngine.formatLinkReport(report);

    // Add Certificate Action Button
    const certBtn = document.createElement('button');
    certBtn.className = 'btn primary-glow';
    certBtn.style.marginTop = '14px';
    certBtn.innerHTML = '📄 Generate Cybercrime Evidence Certificate';
    certBtn.addEventListener('click', () => openCertificateModal(report));
    linkResultsContent.querySelector('.trust-report').appendChild(certBtn);
  };

  mainScanBtn.addEventListener('click', () => {
    if (mainUrlInput.value) executeMainLinkAnalysis(mainUrlInput.value);
  });

  document.querySelectorAll('.sample-chip[data-url]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const url = e.currentTarget.getAttribute('data-url');
      mainUrlInput.value = url;
      executeMainLinkAnalysis(url);
    });
  });

  // MODULE 2: QR Code Guardian
  const qrDropzone = document.getElementById('dash-qr-dropzone');
  const qrInput = document.getElementById('dash-qr-input');
  const qrResultsContent = document.getElementById('qr-results-content');

  if (qrDropzone) qrDropzone.addEventListener('click', () => qrInput.click());

  if (qrInput) {
    qrInput.addEventListener('change', async (e) => {
      if (e.target.files.length > 0) {
        const file = e.target.files[0];
        qrResultsContent.innerHTML = '<div class="results-placeholder"><span class="placeholder-icon">⏳</span><p>Decoding QR Payload locally...</p></div>';
        const result = await QRGuardian.scanAndAnalyzeQR(file);
        renderDashQRResult(result);
      }
    });
  }

  const handleQRScan = async (samplePayload, msg) => {
    qrResultsContent.innerHTML = `<div class="results-placeholder"><span class="placeholder-icon">⏳</span><p>${msg}</p></div>`;
    const result = await QRGuardian.scanAndAnalyzeQR(samplePayload);
    renderDashQRResult(result);
  };

  const btnBad = document.getElementById('dash-qr-bad');
  const btnUpiScam = document.getElementById('dash-qr-upi-scam');
  const btnWifi = document.getElementById('dash-qr-wifi');
  const btnVcard = document.getElementById('dash-qr-vcard');
  const btnGood = document.getElementById('dash-qr-good');
  const visualFakeCard = document.getElementById('visual-fake-qr-card');
  const visualRealCard = document.getElementById('visual-real-qr-card');

  if (btnBad) btnBad.addEventListener('click', () => handleQRScan('sample-phishing-qr', 'Decoding Quishing QR Payload...'));
  if (btnUpiScam) btnUpiScam.addEventListener('click', () => handleQRScan('sample-upi-qr', 'Decoding Reverse Debit Trap QR...'));
  if (btnWifi) btnWifi.addEventListener('click', () => handleQRScan('sample-wifi-qr', 'Decoding Evil Twin Wi-Fi QR...'));
  if (btnVcard) btnVcard.addEventListener('click', () => handleQRScan('sample-vcard-qr', 'Decoding vCard Contact QR...'));
  if (btnGood) btnGood.addEventListener('click', () => handleQRScan('sample-merchant-qr', 'Decoding Merchant UPI QR...'));
  if (visualFakeCard) visualFakeCard.addEventListener('click', () => handleQRScan('sample-phishing-qr', 'Decoding Visual Fake / Scam QR Payload...'));
  if (visualRealCard) visualRealCard.addEventListener('click', () => handleQRScan('sample-merchant-qr', 'Decoding Visual Merchant QR Payload...'));

  function renderDashQRResult(result) {
    if (!result.success) {
      qrResultsContent.innerHTML = `<div class="card"><p>❌ ${result.error}</p></div>`;
      return;
    }
    if (result.linkAnalysis) {
      qrResultsContent.innerHTML = ExplainabilityEngine.formatLinkReport(result.linkAnalysis);
      const certBtn = document.createElement('button');
      certBtn.className = 'btn primary-glow';
      certBtn.style.marginTop = '14px';
      certBtn.innerHTML = '📄 Generate Cybercrime Evidence Certificate';
      certBtn.addEventListener('click', () => openCertificateModal(result.linkAnalysis));
      const reportNode = qrResultsContent.querySelector('.trust-report');
      if (reportNode) reportNode.appendChild(certBtn);
    } else {
      qrResultsContent.innerHTML = `
        <div class="trust-report ${result.upiData && result.upiData.isSuspicious ? 'critical' : 'low'}">
          <h4>📱 Decoded QR Payload:</h4>
          <p class="summary-text">${result.explanation}</p>
        </div>
      `;
    }
  }

  // MODULE 3: Payment Screenshot Forensic Audit
  const paymentDropzone = document.getElementById('dash-payment-dropzone');
  const paymentInput = document.getElementById('dash-payment-input');
  const paymentResultsContent = document.getElementById('payment-results-content');
  const paymentElaBox = document.getElementById('payment-ela-box');

  paymentDropzone.addEventListener('click', () => paymentInput.click());

  paymentInput.addEventListener('change', async (e) => {
    if (e.target.files.length > 0) {
      executeDashPaymentAudit(e.target.files[0]);
    }
  });

  document.getElementById('dash-pay-fake').addEventListener('click', () => {
    executeDashPaymentAudit('sample-fake-receipt');
  });

  document.getElementById('dash-pay-real').addEventListener('click', () => {
    executeDashPaymentAudit('sample-real-receipt');
  });

  async function executeDashPaymentAudit(source) {
    paymentResultsContent.innerHTML = '<div class="results-placeholder"><span class="placeholder-icon">⏳</span><p>Performing Error Level Analysis & Field Integrity Audit...</p></div>';
    paymentElaBox.classList.remove('hidden');

    const tempCanvas = document.createElement('canvas');
    const report = await PaymentVerifier.analyzePaymentProof(source, tempCanvas);

    // Initialize Interactive Split Slider & 4x Lens
    const sliderContainer = document.getElementById('split-slider-container');
    ELAMagnifier.initSplitSliderAndLens(sliderContainer, source, tempCanvas);

    paymentResultsContent.innerHTML = ExplainabilityEngine.formatPaymentReport(report);

    // Add Certificate Action Button
    const certBtn = document.createElement('button');
    certBtn.className = 'btn primary-glow';
    certBtn.style.marginTop = '14px';
    certBtn.innerHTML = '📄 Generate Cybercrime Evidence Certificate';
    certBtn.addEventListener('click', () => openCertificateModal(report));
    paymentResultsContent.querySelector('.trust-report').appendChild(certBtn);
  }
});

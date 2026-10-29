import { LinkAnalyzer } from '../core/link_analyzer.js';
import { QRGuardian } from '../core/qr_guardian.js';
import { PaymentVerifier } from '../core/payment_verifier.js';
import { ExplainabilityEngine } from '../core/explainability.js';

document.addEventListener('DOMContentLoaded', () => {
  // Tab Navigation Setup
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      tab.classList.add('active');
      const targetId = tab.getAttribute('data-tab');
      document.getElementById(targetId).classList.add('active');
    });
  });

  // Module 1: Link & Redirect X-Ray Scan
  const urlInput = document.getElementById('url-input');
  const scanUrlBtn = document.getElementById('scan-url-btn');
  const linkReportContainer = document.getElementById('link-report-container');

  const executeLinkScan = async (url) => {
    linkReportContainer.innerHTML = '<div class="card"><p>⏳ Running 2-Tier Link Scan (ML Features + Redirect X-Ray)...</p></div>';
    const report = await LinkAnalyzer.analyzeUrl(url);
    linkReportContainer.innerHTML = ExplainabilityEngine.formatLinkReport(report);
  };

  scanUrlBtn.addEventListener('click', () => {
    if (urlInput.value) executeLinkScan(urlInput.value);
  });

  document.querySelectorAll('.sample-btn[data-sample]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const sampleUrl = e.target.getAttribute('data-sample');
      urlInput.value = sampleUrl;
      executeLinkScan(sampleUrl);
    });
  });

  // Module 2: QR Guardian Scan
  const qrDropzone = document.getElementById('qr-dropzone');
  const qrFileInput = document.getElementById('qr-file-input');
  const qrReportContainer = document.getElementById('qr-report-container');

  qrDropzone.addEventListener('click', () => qrFileInput.click());

  qrFileInput.addEventListener('change', async (e) => {
    if (e.target.files.length > 0) {
      const file = e.target.files[0];
      qrReportContainer.innerHTML = '<div class="card"><p>⏳ Decoding QR Code Payload locally...</p></div>';
      const result = await QRGuardian.scanAndAnalyzeQR(file);
      renderQRResult(result);
    }
  });

  document.getElementById('sample-qr-phishing').addEventListener('click', async () => {
    qrReportContainer.innerHTML = '<div class="card"><p>⏳ Decoding QR Sample...</p></div>';
    const result = await QRGuardian.scanAndAnalyzeQR('sample-phishing-qr');
    renderQRResult(result);
  });

  document.getElementById('sample-qr-upi').addEventListener('click', async () => {
    qrReportContainer.innerHTML = '<div class="card"><p>⏳ Decoding UPI QR Sample...</p></div>';
    const result = await QRGuardian.scanAndAnalyzeQR('sample-upi-qr');
    renderQRResult(result);
  });

  function renderQRResult(result) {
    if (!result.success) {
      qrReportContainer.innerHTML = `<div class="card"><p>❌ ${result.error}</p></div>`;
      return;
    }
    if (result.linkAnalysis) {
      qrReportContainer.innerHTML = ExplainabilityEngine.formatLinkReport(result.linkAnalysis);
    } else {
      qrReportContainer.innerHTML = `
        <div class="trust-report low">
          <h4>📱 Decoded QR Payload:</h4>
          <p class="summary-text">${result.explanation}</p>
        </div>
      `;
    }
  }

  // Module 3: Payment Proof Forensic Audit
  const paymentDropzone = document.getElementById('payment-dropzone');
  const paymentFileInput = document.getElementById('payment-file-input');
  const paymentReportContainer = document.getElementById('payment-report-container');
  const elaCanvas = document.getElementById('ela-canvas');
  const elaPreviewCard = document.getElementById('ela-preview-card');

  paymentDropzone.addEventListener('click', () => paymentFileInput.click());

  paymentFileInput.addEventListener('change', async (e) => {
    if (e.target.files.length > 0) {
      const file = e.target.files[0];
      executePaymentAudit(file);
    }
  });

  document.getElementById('sample-payment-fake').addEventListener('click', () => {
    executePaymentAudit('sample-fake-receipt');
  });

  document.getElementById('sample-payment-real').addEventListener('click', () => {
    executePaymentAudit('sample-real-receipt');
  });

  async function executePaymentAudit(source) {
    paymentReportContainer.innerHTML = '<div class="card"><p>⏳ Running Error Level Analysis (ELA) & Field OCR Check...</p></div>';
    elaPreviewCard.classList.remove('hidden');
    
    const report = await PaymentVerifier.analyzePaymentProof(source, elaCanvas);
    paymentReportContainer.innerHTML = ExplainabilityEngine.formatPaymentReport(report);
  }
});

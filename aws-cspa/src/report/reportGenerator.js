/**
 * Report Generator
 * ================
 * Produces a self-contained HTML risk report from the assessment results.
 *
 * Risk Score Formula (Section 4.3.3 of dissertation):
 *   score = 100 - (critical * 25) - (high * 10) - (medium * 5) - (low * 2)
 *   score = Math.max(0, score)
 *
 * Severity colour coding:
 *   Critical : Red    (#dc2626)
 *   High     : Orange (#ea580c)
 *   Medium   : Amber  (#ca8a04)
 *   Low      : Blue   (#2563eb)
 *   Passed   : Green  (#16a34a)
 */

import fs from 'fs-extra';
import path from 'path';

const SEVERITY = {
  critical: { color: '#dc2626', bg: '#fef2f2', border: '#fca5a5', label: 'CRITICAL' },
  high:     { color: '#ea580c', bg: '#fff7ed', border: '#fdba74', label: 'HIGH'     },
  medium:   { color: '#ca8a04', bg: '#fefce8', border: '#fde047', label: 'MEDIUM'   },
  low:      { color: '#2563eb', bg: '#eff6ff', border: '#93c5fd', label: 'LOW'      }
};

/**
 * Calculates overall risk score using weighted severity formula.
 * As defined in Section 4.3.3 and Table 4.1 of the dissertation.
 *
 * Weights: Critical=25, High=10, Medium=5, Low=2
 * Score range: 0 (worst) to 100 (fully compliant)
 */
function calculateRiskScore(summary) {
  const raw = 100
    - (summary.critical * 25)
    - (summary.high     * 10)
    - (summary.medium   *  5)
    - (summary.low      *  2);
  return Math.max(0, raw);
}

function getRiskLabel(score) {
  if (score >= 80) return { label: 'Low Risk',      color: '#16a34a' };
  if (score >= 60) return { label: 'Medium Risk',   color: '#ca8a04' };
  if (score >= 40) return { label: 'High Risk',     color: '#ea580c' };
  return              { label: 'Critical Risk',  color: '#dc2626' };
}

function getAllFindings(checks) {
  return Object.entries(checks).flatMap(([service, data]) =>
    (data.findings || []).map(f => ({ ...f, service: service.toUpperCase() }))
  );
}

function renderFinding(f) {
  const cfg = SEVERITY[f.severity] || SEVERITY.low;
  return `
    <div style="border:1px solid ${cfg.border};background:${cfg.bg};border-radius:8px;padding:16px;margin-bottom:12px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap;">
        <span style="background:${cfg.color};color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;letter-spacing:0.05em;">${cfg.label}</span>
        <span style="font-size:11px;color:#6b7280;background:#f3f4f6;padding:2px 8px;border-radius:4px;">${f.cisControl || ''}</span>
        <strong style="color:#111;font-size:14px;">${f.check}</strong>
      </div>
      <p style="margin:0 0 6px;color:#374151;font-size:13px;"><strong>Resource:</strong> <code style="background:#e5e7eb;padding:2px 6px;border-radius:4px;font-size:12px;">${f.resource}</code></p>
      <p style="margin:0 0 6px;color:#374151;font-size:13px;"><strong>Detail:</strong> ${f.detail}</p>
      <p style="margin:0;color:#374151;font-size:13px;"><strong>Recommendation:</strong> ${f.recommendation}</p>
    </div>`;
}

function renderSection(title, icon, findings) {
  const count = findings.length;
  const content = count === 0
    ? `<p style="color:#16a34a;font-weight:600;font-size:13px;">No issues detected. All checks passed.</p>`
    : findings.map(renderFinding).join('');

  return `
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:24px;margin-bottom:20px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid #f1f5f9;">
        <span style="font-size:20px;">${icon}</span>
        <h2 style="margin:0;font-size:15px;font-weight:600;color:#111;">${title}</h2>
        <span style="margin-left:auto;font-size:12px;color:#6b7280;background:#f3f4f6;padding:3px 10px;border-radius:99px;">${count} finding${count !== 1 ? 's' : ''}</span>
      </div>
      ${content}
    </div>`;
}

export async function generateReport(results) {
  const score = calculateRiskScore(results.summary);
  const risk = getRiskLabel(score);
  const allFindings = getAllFindings(results.checks);
  const totalFindings = allFindings.length;

  const s3Findings  = allFindings.filter(f => f.service === 'S3');
  const iamFindings = allFindings.filter(f => f.service === 'IAM');
  const ctFindings  = allFindings.filter(f => f.service === 'CLOUDTRAIL');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>AWS Security Posture Assessment Report</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:'IBM Plex Sans',sans-serif;background:#f8fafc;color:#1e293b;}
    .header{background:#0f172a;color:#fff;padding:32px 40px;}
    .header h1{font-size:20px;font-weight:700;letter-spacing:-0.02em;margin-bottom:6px;}
    .header p{color:#94a3b8;font-size:12px;font-family:'IBM Plex Mono',monospace;}
    .container{max-width:900px;margin:0 auto;padding:32px 20px;}
    .score-card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px;margin-bottom:28px;display:flex;align-items:center;gap:32px;}
    .score-ring{width:100px;height:100px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;border:7px solid ${risk.color};flex-shrink:0;}
    .score-ring .num{font-size:28px;font-weight:700;color:${risk.color};line-height:1;}
    .score-ring .lbl{font-size:10px;color:#6b7280;margin-top:2px;}
    .score-detail h2{font-size:18px;font-weight:700;color:${risk.color};margin-bottom:4px;}
    .score-detail p{color:#6b7280;font-size:13px;margin-bottom:12px;}
    .pills{display:flex;gap:8px;flex-wrap:wrap;}
    .pill{padding:4px 12px;border-radius:99px;font-size:12px;font-weight:600;}
    .p-c{background:#fef2f2;color:#991b1b;}
    .p-h{background:#fff7ed;color:#9a3412;}
    .p-m{background:#fefce8;color:#854d0e;}
    .p-l{background:#eff6ff;color:#1e40af;}
    .p-p{background:#f0fdf4;color:#166534;}
    .cis-table{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px;}
    .cis-table th{text-align:left;padding:8px 12px;background:#f8fafc;border:1px solid #e5e7eb;font-weight:600;color:#374151;}
    .cis-table td{padding:8px 12px;border:1px solid #e5e7eb;color:#374151;}
    .cis-pass{color:#16a34a;font-weight:600;}
    .cis-fail{color:#dc2626;font-weight:600;}
    .footer{text-align:center;color:#94a3b8;font-size:12px;padding:24px;font-family:'IBM Plex Mono',monospace;}
  </style>
</head>
<body>
<div class="header">
  <h1>AWS Cloud Security Posture Assessment</h1>
  <p>Generated: ${new Date(results.timestamp).toUTCString()} | Tool: aws-cspa v1.0.0 | MSc Cybersecurity | Arden University Berlin</p>
</div>

<div class="container">

  <div class="score-card">
    <div class="score-ring">
      <span class="num">${score}</span>
      <span class="lbl">/ 100</span>
    </div>
    <div class="score-detail">
      <h2>${risk.label}</h2>
      <p>${totalFindings} misconfiguration${totalFindings !== 1 ? 's' : ''} detected across S3, IAM, and CloudTrail checks. Score calculated using weighted severity formula: Critical(x25) + High(x10) + Medium(x5) + Low(x2).</p>
      <div class="pills">
        <span class="pill p-c">Critical: ${results.summary.critical}</span>
        <span class="pill p-h">High: ${results.summary.high}</span>
        <span class="pill p-m">Medium: ${results.summary.medium}</span>
        <span class="pill p-l">Low: ${results.summary.low}</span>
        <span class="pill p-p">Passed: ${results.summary.passed}</span>
      </div>
    </div>
  </div>

  <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:24px;margin-bottom:20px;">
    <h2 style="font-size:15px;font-weight:600;margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid #f1f5f9;">CIS AWS Foundations Benchmark v2.0.0 Coverage</h2>
    <table class="cis-table">
      <thead><tr><th>CIS Control</th><th>Description</th><th>FR ID</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>CIS 2.1.1, 2.1.2</td><td>S3 Public Access Block enabled</td><td>FR1</td><td class="${s3Findings.filter(f=>f.cisControl?.includes('2.1.1')).length > 0 ? 'cis-fail">FAIL' : 'cis-pass">PASS'}</td></tr>
        <tr><td>CIS 2.1.5</td><td>S3 bucket ACL no public grants</td><td>FR2</td><td class="${s3Findings.filter(f=>f.cisControl?.includes('2.1.5')).length > 0 ? 'cis-fail">FAIL' : 'cis-pass">PASS'}</td></tr>
        <tr><td>CIS 1.1</td><td>No wildcard IAM policies</td><td>FR3</td><td class="${iamFindings.filter(f=>f.cisControl?.includes('1.1')).length > 0 ? 'cis-fail">FAIL' : 'cis-pass">PASS'}</td></tr>
        <tr><td>CIS 1.16</td><td>IAM policies not attached to users</td><td>FR4</td><td class="${iamFindings.filter(f=>f.cisControl?.includes('1.16')).length > 0 ? 'cis-fail">FAIL' : 'cis-pass">PASS'}</td></tr>
        <tr><td>CIS 3.3</td><td>CloudTrail actively logging</td><td>FR5, FR8</td><td class="${ctFindings.filter(f=>f.cisControl?.includes('3.3')).length > 0 ? 'cis-fail">FAIL' : 'cis-pass">PASS'}</td></tr>
        <tr><td>CIS 3.1</td><td>CloudTrail multi-region enabled</td><td>FR6</td><td class="${ctFindings.filter(f=>f.cisControl?.includes('3.1')).length > 0 ? 'cis-fail">FAIL' : 'cis-pass">PASS'}</td></tr>
        <tr><td>CIS 3.2</td><td>CloudTrail log file validation on</td><td>FR7</td><td class="${ctFindings.filter(f=>f.cisControl?.includes('3.2')).length > 0 ? 'cis-fail">FAIL' : 'cis-pass">PASS'}</td></tr>
      </tbody>
    </table>
  </div>

  ${renderSection('S3 Bucket Public Access', 'S3', s3Findings)}
  ${renderSection('IAM Policy Permissions', 'IAM', iamFindings)}
  ${renderSection('CloudTrail Audit Logging', 'CT', ctFindings)}

</div>

<div class="footer">
  AWS Cloud Security Posture Assessment Tool (aws-cspa v1.0.0) | MSc Cybersecurity | Arden University Berlin | Student: 24156787
</div>
</body>
</html>`;

  await fs.ensureDir('./reports');
  const filename = `report-${Date.now()}.html`;
  const filepath = path.resolve(`./reports/${filename}`);
  await fs.writeFile(filepath, html, 'utf8');
  return filepath;
}

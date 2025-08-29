<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>SimplCyber Loss Exposure Report – {{domain}}</title>

  <!-- Typography: Inter with tabular numerals for finance alignment -->
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

  <style>
    :root {
      --bg: #f6f7f9;
      --card: #ffffff;
      --ink: #0f172a;
      --ink-2: #334155;
      --ink-3: #64748b;

      --accent: #0f766e;
      --accent-2: #115e59;
      --accent-soft: #e6fffb;

      --border: #e5e7eb;
      --critical: #b91c1c;
      --high: #c2410c;
      --medium: #a16207;
      --low: #15803d;
      --info: #0369a1;

      --radius-lg: 14px;
      --radius-md: 10px;
      --shadow-1: 0 2px 10px rgba(15, 23, 42, 0.05);

      --fs-0: 0.875rem;
      --fs-1: 1rem;
      --fs-2: 1.125rem;
      --fs-3: 1.375rem;
      --fs-4: 1.75rem;
      --fs-5: clamp(1.5rem, 3.2vw, 2.25rem);
      --fs-6: clamp(1.75rem, 4.0vw, 3rem);

      --space-1: 6px;
      --space-2: 10px;
      --space-3: 14px;
      --space-4: 20px;
      --space-5: 28px;
      --space-6: 36px;
      --space-7: 48px;
      --space-8: 64px;
    }

    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.55;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      font-variant-numeric: tabular-nums lining-nums;
    }

    .report {
      max-width: 1100px;
      margin: var(--space-7) auto;
      padding: 0 var(--space-4);
    }

    .header {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-1);
      padding: var(--space-6) var(--space-6);
    }
    .header-top {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: var(--space-3);
      justify-content: space-between;
      margin-bottom: var(--space-3);
    }
    .brand {
      display: flex;
      gap: var(--space-3);
      align-items: center;
    }
    .brand-mark {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: radial-gradient(120% 120% at 20% 20%, #14b8a6 0%, #0f766e 60%, #115e59 100%);
      box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.25);
    }
    .title {
      display: grid;
      gap: 2px;
    }
    .title h1 {
      margin: 0;
      font-size: var(--fs-5);
      letter-spacing: -0.015em;
      font-weight: 700;
    }
    .subtitle {
      color: var(--ink-3);
      font-size: var(--fs-0);
    }
    .report-meta {
      text-align: right;
      color: var(--ink-3);
      font-size: var(--fs-0);
    }
    .meta-pill {
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent-2);
      font-weight: 600;
      border: 1px solid #b2f5ea;
      margin-left: var(--space-2);
      font-size: 0.8rem;
    }

    .eal {
      margin-top: var(--space-6);
      display: grid;
      gap: var(--space-4);
    }
    .eal h2 {
      font-size: var(--fs-3);
      margin: 0;
    }
    .eal-cards {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: var(--space-4);
    }
    .eal-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-1);
      padding: var(--space-4);
      display: grid;
      gap: var(--space-3);
      min-height: 160px;
    }
    .eal-card .label {
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 700;
      font-size: 0.78rem;
      color: var(--ink-3);
    }
    .amount-wrap {
      display: grid;
      justify-items: end;
      gap: 4px;
    }
    .amount-head {
      font-weight: 700;
      font-size: clamp(1.5rem, 4vw, 2.5rem);
      color: var(--accent-2);
      line-height: 1.1;
      white-space: nowrap;
    }
    .amount-full {
      font-size: 0.9rem;
      color: var(--ink-3);
      white-space: nowrap;
    }
    .note {
      color: var(--ink-3);
      font-size: 0.9rem;
    }

    .overview {
      margin-top: var(--space-6);
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-1);
      padding: var(--space-4);
      display: grid;
      gap: var(--space-4);
    }
    .overview h3 {
      margin: 0;
      font-size: var(--fs-2);
    }
    .sev-grid {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: var(--space-3);
    }
    .sev-card {
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: var(--space-3);
      text-align: right;
      box-shadow: var(--shadow-1);
      background: #fff;
    }
    .sev-card .count {
      font-size: var(--fs-4);
      font-weight: 700;
      line-height: 1.1;
      margin-bottom: 4px;
    }
    .sev-card .label {
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--ink-3);
      font-weight: 600;
    }
    .sev-critical .count { color: var(--critical); }
    .sev-high .count { color: var(--high); }
    .sev-medium .count { color: var(--medium); }
    .sev-low .count { color: var(--low); }
    .sev-info .count { color: var(--info); }

    .breakdown {
      margin-top: var(--space-6);
      display: grid;
      gap: var(--space-3);
    }
    .breakdown h3 {
      margin: 0;
      font-size: var(--fs-2);
    }
    .breakdown-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: var(--space-3);
    }
    .break-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-1);
      padding: var(--space-3);
      display: grid;
      gap: 8px;
      min-height: 120px;
    }
    .break-card .k {
      color: var(--ink-2);
      font-weight: 600;
    }
    .break-card .v {
      text-align: right;
      font-weight: 700;
      font-size: 1.1rem;
      color: var(--accent-2);
      white-space: nowrap;
    }
    .break-card .hint {
      color: var(--ink-3);
      font-size: 0.85rem;
    }

    .findings {
      margin-top: var(--space-6);
    }
    .findings h3 {
      margin: 0 0 var(--space-3) 0;
      font-size: var(--fs-2);
    }
    .finding {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-1);
      margin-bottom: var(--space-3);
      overflow: hidden;
    }
    .finding-head {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: var(--space-3);
      align-items: center;
      padding: var(--space-3) var(--space-4);
      border-bottom: 1px solid var(--border);
      background: #fbfdff;
    }
    .sev-badge {
      font-size: 0.8rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: #fff;
    }
    .sev-badge.critical { color: var(--critical); border-color: #fecaca; background: #fff5f5; }
    .sev-badge.high { color: var(--high); border-color: #fed7aa; background: #fff7ed; }
    .sev-badge.medium { color: var(--medium); border-color: #fde68a; background: #fffbeb; }
    .sev-badge.low { color: var(--low); border-color: #bbf7d0; background: #f0fdf4; }
    .sev-badge.info { color: var(--info); border-color: #bae6fd; background: #f0f9ff; }

    .finding-title {
      font-weight: 700;
      font-size: var(--fs-1);
      color: var(--ink);
    }
    .finding-body {
      padding: var(--space-4);
      color: var(--ink-2);
      display: grid;
      gap: var(--space-3);
    }
    .recommend {
      border-left: 3px solid var(--accent);
      background: #f8fffe;
      padding: var(--space-3);
      border-radius: 6px;
      color: var(--ink-2);
    }
    .recommend strong {
      color: var(--accent-2);
    }

    .method {
      margin-top: var(--space-6);
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-1);
      padding: var(--space-4);
      color: var(--ink-2);
    }

    .footer {
      color: var(--ink-3);
      font-size: var(--fs-0);
      text-align: center;
      padding: var(--space-6) var(--space-4) var(--space-7);
    }

    @media print {
      body { background: #fff; }
      .report { margin: 0; padding: 0; }
      .header, .eal-card, .finding, .break-card { box-shadow: none; }
      .finding, .eal-card, .break-card { page-break-inside: avoid; }
    }

    @media (max-width: 980px) {
      .eal-cards { grid-template-columns: 1fr; }
      .sev-grid { grid-template-columns: repeat(3, 1fr); }
      .breakdown-grid { grid-template-columns: repeat(2, 1fr); }
      .report-meta { text-align: left; }
    }
    @media (max-width: 560px) {
      .sev-grid { grid-template-columns: repeat(2, 1fr); }
      .breakdown-grid { grid-template-columns: 1fr; }
      .amount-head { font-size: clamp(1.4rem, 6vw, 2rem); }
    }
  </style>
</head>
<body>
  <main class="report">

    <section class="header" aria-labelledby="report-title">
      <div class="header-top">
        <div class="brand">
          <div class="brand-mark" aria-hidden="true"></div>
          <div class="title">
            <h1 id="report-title">SimplCyber Loss Exposure Report</h1>
            <div class="subtitle">{{domain}}</div>
          </div>
        </div>
        <div class="report-meta">
          <span>Generated: {{report_date}}</span>
          <span class="meta-pill">Cyber Loss Snapshot</span>
        </div>
      </div>

      <p class="note">
        This report quantifies <strong>financial losses driven by cybersecurity risks</strong>. It translates technical
        vulnerabilities into dollar exposure, enabling boards and executives to prioritize remediation by business impact.
      </p>
    </section>

    {{#if eal_summary}}
    <section class="eal" aria-labelledby="eal-title">
      <h2 id="eal-title">Expected Annual Loss (EAL)</h2>

      <div class="eal-cards">
        <article class="eal-card" aria-labelledby="eal-cons-label">
          <div class="label" id="eal-cons-label">Conservative (p90)</div>
          <div class="amount-wrap">
            <div class="amount-head">${{format_abbrev eal_summary.total_eal_low}}</div>
            <div class="amount-full">${{format_currency eal_summary.total_eal_low}}</div>
          </div>
          <div class="note">High-confidence bound assuming partial exploitability.</div>
        </article>

        <article class="eal-card" aria-labelledby="eal-ml-label">
          <div class="label" id="eal-ml-label">Most Likely</div>
          <div class="amount-wrap">
            <div class="amount-head">${{format_abbrev eal_summary.total_eal_ml}}</div>
            <div class="amount-full">${{format_currency eal_summary.total_eal_ml}}</div>
          </div>
          <div class="note">Expected annual loss from current risk profile.</div>
        </article>

        <article class="eal-card" aria-labelledby="eal-wc-label">
          <div class="label" id="eal-wc-label">Worst Case</div>
          <div class="amount-wrap">
            <div class="amount-head">${{format_abbrev eal_summary.total_eal_high}}</div>
            <div class="amount-full">${{format_currency eal_summary.total_eal_high}}</div>
          </div>
          <div class="note">Upper bound under stacked adverse conditions.</div>
        </article>
      </div>
    </section>
    {{/if}}

    <section class="overview" aria-labelledby="overview-title">
      <h3 id="overview-title">Executive Summary</h3>
      <p class="note">
        {{total_findings}} total findings across {{modules_completed}} modules (runtime: {{duration_seconds}}s).
        {{#if has_critical_findings}}<strong>{{severity_counts.CRITICAL}} critical</strong> require immediate action.{{/if}}
        {{#if eal_summary}} Most likely loss: <strong>${{format_currency eal_summary.total_eal_ml}}</strong>; worst case
        exposure: <strong>${{format_currency eal_summary.total_eal_high}}</strong>. {{/if}}
      </p>

      <div class="sev-grid" role="list">
        <div class="sev-card sev-critical" role="listitem">
          <div class="count">{{severity_counts.CRITICAL}}</div>
          <div class="label">Critical</div>
        </div>
        <div class="sev-card sev-high" role="listitem">
          <div class="count">{{severity_counts.HIGH}}</div>
          <div class="label">High</div>
        </div>
        <div class="sev-card sev-medium" role="listitem">
          <div class="count">{{severity_counts.MEDIUM}}</div>
          <div class="label">Medium</div>
        </div>
        <div class="sev-card sev-low" role="listitem">
          <div class="count">{{severity_counts.LOW}}</div>
          <div class="label">Low</div>
        </div>
        <div class="sev-card sev-info" role="listitem">
          <div class="count">{{severity_counts.INFO}}</div>
          <div class="label">Info</div>
        </div>
      </div>
    </section>

    {{#if eal_summary}}
    <section class="breakdown" aria-labelledby="breakdown-title">
      <h3 id="breakdown-title">Risk Category Breakdown</h3>
      <div class="breakdown-grid">
        {{#if eal_summary.cyber_total_ml}}
        <article class="break-card">
          <div class="k">Cybersecurity</div>
          <div class="v">${{format_abbrev eal_summary.cyber_total_ml}}</div>
          <div class="hint">Vulnerabilities, exposures, technical gaps</div>
        </article>
        {{/if}}

        {{#if eal_summary.legal_total_ml}}
        <article class="break-card">
          <div class="k">Legal &amp; Compliance</div>
          <div class="v">${{format_abbrev eal_summary.legal_total_ml}}</div>
          <div class="hint">Regulatory + contractual</div>
        </article>
        {{/if}}

        {{#if eal_summary.cloud_total_ml}}
        <article class="break-card">
          <div class="k">Cloud Infrastructure</div>
          <div class="v">${{format_abbrev eal_summary.cloud_total_ml}}</div>
          <div class="hint">Abuse, DoW, cost amplification</div>
        </article>
        {{/if}}

        {{#if eal_summary.total_eal_daily}}
        <article class="break-card">
          <div class="k">Daily Exposure</div>
          <div class="v">${{format_abbrev eal_summary.total_eal_daily}}/day</div>
          <div class="hint">Modeled ongoing exposure</div>
        </article>
        {{/if}}
      </div>
    </section>
    {{/if}}

    {{#if findings.length}}
    <section class="findings" aria-labelledby="findings-title">
      <h3 id="findings-title">Security Findings</h3>

      {{#each findings}}
      <article class="finding" aria-labelledby="f-{{@index}}-title">
        <header class="finding-head">
          <span class="sev-badge {{toLowerCase severity}}">{{severity}}</span>
          <div id="f-{{@index}}-title" class="finding-title">{{title}}</div>
        </header>
        <div class="finding-body">
          {{#if description}}
          <div>{{description}}</div>
          {{/if}}
          <div class="recommend">
            <strong>Recommended Action:</strong> Review and remediate this {{toLowerCase severity}} severity issue to
            reduce modeled loss.
          </div>
        </div>
      </article>
      {{/each}}
    </section>
    {{/if}}

    {{#if eal_summary}}
    <section class="method" aria-labelledby="method-title">
      <h3 id="method-title">Methodology</h3>
      <p>
        EAL is computed from likelihood × impact across identified findings, adjusted for exposure windows, compensating
        controls, and industry prevalence. Values are point-in-time and should be re-baselined quarterly.
      </p>
    </section>
    {{/if}}

    <footer class="footer">
      Report generated by <strong>SimplCyber</strong> on {{report_date}}.
    </footer>
  </main>
</body>
</html>


If you need a Handlebars helper for format_abbrev, here’s a safe version:
// Node/Express Handlebars helper
hbs.handlebars.registerHelper('format_abbrev', function (value) {
  const n = Number(value) || 0;
  const abs = Math.abs(n);
  const fmt = (v, suffix) => `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)}${suffix}`;
  if (abs >= 1e12) return fmt(n / 1e12, 'T');
  if (abs >= 1e9)  return fmt(n / 1e9,  'B');
  if (abs >= 1e6)  return fmt(n / 1e6,  'M');
  if (abs >= 1e3)  return fmt(n / 1e3,  'k');
  return n.toLocaleString();
}); 
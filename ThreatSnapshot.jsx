import React, { useState, useEffect } from 'react';
import { Shield, TrendingUp, AlertCircle, ArrowUpRight, Share2, Download, Mail } from 'lucide-react';

// Utility functions
const formatCurrency = (value) => {
  if (!value) return '$0';
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(value);
};

const formatDate = (dateStr) => {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
};

// Financial Impact Hero Section
const FinancialImpactHero = ({ data }) => {
  const [animatedValues, setAnimatedValues] = useState({
    eal_ml_total: 0,
    eal_daily_total: 0,
    eal_low_total: 0,
    eal_high_total: 0
  });
  
  useEffect(() => {
    const timer = setTimeout(() => setAnimatedValues(data), 200);
    return () => clearTimeout(timer);
  }, [data]);

  return (
    <section className="relative bg-gradient-to-br from-red-50 via-orange-50 to-amber-50 rounded-3xl border border-orange-200 overflow-hidden">
      {/* Background decoration */}
      <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 to-orange-500/5" />
      <div className="absolute -top-24 -right-24 w-96 h-96 bg-gradient-to-br from-orange-200 to-red-200 rounded-full blur-3xl opacity-30" />
      
      <div className="relative p-12">
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-3 px-6 py-3 bg-white/80 backdrop-blur-sm rounded-full border border-orange-200 mb-6">
            <AlertCircle className="w-5 h-5 text-orange-600" />
            <span className="text-orange-900 font-medium">Financial Risk Exposure</span>
          </div>
          <h2 className="text-4xl font-light text-gray-900 mb-4">Annual Loss Exposure</h2>
          <div className="text-6xl font-extralight text-orange-900 mb-4">
            {formatCurrency(animatedValues.eal_ml_total)}
          </div>
          <div className="text-lg text-gray-700">
            Range: {formatCurrency(animatedValues.eal_low_total)} - {formatCurrency(animatedValues.eal_high_total)}
          </div>
        </div>

        {/* Secondary metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="text-center p-8 bg-white/60 backdrop-blur-sm rounded-2xl border border-white/50">
            <div className="text-3xl font-light text-red-900 mb-2">
              {formatCurrency(animatedValues.eal_daily_total)}
            </div>
            <div className="text-sm text-gray-700 font-medium">Daily Cost if Exploited</div>
          </div>
          <div className="text-center p-8 bg-white/60 backdrop-blur-sm rounded-2xl border border-white/50">
            <div className="text-3xl font-light text-red-900 mb-2">
              {data.overall_risk_score}/100
            </div>
            <div className="text-sm text-gray-700 font-medium">Overall Risk Score</div>
          </div>
        </div>
      </div>
    </section>
  );
};

// Risk Score Gauge (Secondary Position)
const RiskScoreGauge = ({ score }) => {
  const [animatedScore, setAnimatedScore] = useState(0);
  
  useEffect(() => {
    const timer = setTimeout(() => setAnimatedScore(score), 300);
    return () => clearTimeout(timer);
  }, [score]);
  
  const getGradient = (score) => {
    if (score <= 30) return 'from-emerald-400 to-teal-500';
    if (score <= 60) return 'from-amber-400 to-orange-500';
    if (score <= 80) return 'from-orange-500 to-red-500';
    return 'from-red-500 to-red-600';
  };
  
  const getRiskLevel = (score) => {
    if (score <= 30) return { label: 'Low Risk', color: 'text-emerald-700', bg: 'bg-emerald-50' };
    if (score <= 60) return { label: 'Moderate Risk', color: 'text-amber-700', bg: 'bg-amber-50' };
    if (score <= 80) return { label: 'High Risk', color: 'text-orange-700', bg: 'bg-orange-50' };
    return { label: 'Critical Risk', color: 'text-red-700', bg: 'bg-red-50' };
  };
  
  const riskLevel = getRiskLevel(animatedScore);
  
  return (
    <div className="bg-white rounded-2xl border border-gray-200 p-8">
      <h3 className="text-lg font-medium text-gray-900 mb-6">Security Risk Score</h3>
      
      <div className="text-center">
        <div className={`text-6xl font-extralight bg-gradient-to-br ${getGradient(animatedScore)} bg-clip-text text-transparent mb-4`}>
          {animatedScore}
        </div>
        <div className="text-gray-600 text-lg mb-6">out of 100</div>
        
        <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-full ${riskLevel.bg}`}>
          <span className={`text-sm font-medium ${riskLevel.color}`}>{riskLevel.label}</span>
        </div>
        
        {/* Progress bar */}
        <div className="mt-6">
          <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
            <div 
              className={`h-full bg-gradient-to-r ${getGradient(animatedScore)} transition-all duration-1000 ease-out`}
              style={{ width: `${animatedScore}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

// Severity Distribution Chart
const SeverityDistribution = ({ data }) => {
  const total = Object.values(data).reduce((a, b) => a + b, 0);
  const severities = [
    { key: 'critical_count', label: 'Critical', color: 'bg-red-500' },
    { key: 'high_count', label: 'High', color: 'bg-orange-500' },
    { key: 'medium_count', label: 'Medium', color: 'bg-amber-500' },
    { key: 'low_count', label: 'Low', color: 'bg-emerald-500' },
    { key: 'info_count', label: 'Info', color: 'bg-blue-500' },
  ];
  
  return (
    <div className="bg-white rounded-2xl border border-gray-200 p-8">
      <h3 className="text-lg font-medium text-gray-900 mb-6">Finding Distribution</h3>
      
      <div className="space-y-4">
        {severities.map((sev) => {
          const count = data[sev.key] || 0;
          const percentage = total > 0 ? (count / total) * 100 : 0;
          
          return (
            <div key={sev.key}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${sev.color}`} />
                  <span className="text-sm font-medium text-gray-700">{sev.label}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xl font-light text-gray-900">{count}</span>
                  <span className="text-sm text-gray-500">({percentage.toFixed(0)}%)</span>
                </div>
              </div>
              <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                <div 
                  className={`h-full ${sev.color} transition-all duration-1000 ease-out`}
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
      
      <div className="mt-6 pt-6 border-t border-gray-100">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600">Total Findings</span>
          <span className="text-2xl font-light text-gray-900">{total}</span>
        </div>
      </div>
    </div>
  );
};

// Category Breakdown
const CategoryBreakdown = ({ data }) => {
  const severityColors = {
    CRITICAL: 'from-red-500 to-red-600',
    HIGH: 'from-orange-500 to-orange-600',
    MEDIUM: 'from-amber-500 to-amber-600',
    LOW: 'from-emerald-500 to-emerald-600',
    INFO: 'from-blue-500 to-blue-600',
  };
  
  return (
    <div className="bg-white rounded-2xl border border-gray-200 p-8">
      <h3 className="text-lg font-medium text-gray-900 mb-6">Risk Categories</h3>
      
      <div className="space-y-3">
        {data.map((category, index) => (
          <div 
            key={index}
            className="flex items-center justify-between p-4 rounded-xl border border-gray-200 hover:border-gray-300 transition-colors"
          >
            <div className="flex items-center gap-4">
              <div className={`w-1 h-12 bg-gradient-to-b ${severityColors[category.max_severity]} rounded-full`} />
              <div>
                <h4 className="font-medium text-gray-900 text-sm">{category.display_name}</h4>
                <p className="text-xs text-gray-600 mt-1">Max: {category.max_severity}</p>
              </div>
            </div>
            <div className="text-center">
              <div className="text-xl font-light text-gray-900">{category.count}</div>
              <div className="text-xs text-gray-500">findings</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// Simplified Finding Summary (No Remediation Details)
const FindingSummary = ({ findings }) => {
  if (!findings || findings.length === 0) {
    return (
      <div className="bg-white rounded-2xl border border-gray-200 p-8 text-center">
        <p className="text-gray-500">No critical findings to display</p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl border border-gray-200 p-8">
      <h3 className="text-lg font-medium text-gray-900 mb-6">Critical & High Priority Issues</h3>
      
      <div className="space-y-4">
        {findings.slice(0, 5).map((finding) => {
          const severityColors = {
            CRITICAL: 'bg-red-100 text-red-800 border-red-200',
            HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
            MEDIUM: 'bg-amber-100 text-amber-800 border-amber-200'
          };
          
          return (
            <div key={finding.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-xl">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <span className={`px-2 py-1 rounded-full text-xs font-medium border ${severityColors[finding.severity]}`}>
                    {finding.severity}
                  </span>
                  {finding.cve_id && (
                    <span className="px-2 py-1 rounded-full text-xs font-mono bg-gray-100 text-gray-700 border border-gray-200">
                      {finding.cve_id}
                    </span>
                  )}
                </div>
                <h4 className="font-medium text-gray-900 text-sm">{finding.finding_type_display}</h4>
                <p className="text-xs text-gray-600 mt-1">{finding.asset_name}</p>
              </div>
              <div className="text-right ml-4">
                <div className="text-lg font-light text-gray-900">{formatCurrency(finding.eal_ml)}</div>
                <div className="text-xs text-gray-500">Annual loss</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Share Actions Component
const ShareActions = ({ scanId, onDownload, onEmail, onShare }) => {
  return (
    <div className="flex items-center gap-3">
      <button 
        onClick={onShare}
        className="flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition-colors font-medium"
      >
        <Share2 className="w-4 h-4" />
        Share Your Snapshot
      </button>
      <button 
        onClick={onDownload}
        className="flex items-center gap-2 px-4 py-3 bg-gray-100 text-gray-700 rounded-xl hover:bg-gray-200 transition-colors"
      >
        <Download className="w-4 h-4" />
        Download PDF
      </button>
      <button 
        onClick={onEmail}
        className="flex items-center gap-2 px-4 py-3 bg-gray-100 text-gray-700 rounded-xl hover:bg-gray-200 transition-colors"
      >
        <Mail className="w-4 h-4" />
        Email Report
      </button>
    </div>
  );
};

// Main Threat Snapshot Component
export default function ThreatSnapshot({ scanId }) {
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch report data from your backend
  useEffect(() => {
    const fetchReportData = async () => {
      if (!scanId) {
        setError('No scan ID provided');
        setLoading(false);
        return;
      }

      try {
        // Replace with your actual Supabase endpoint
        const response = await fetch(`/api/reports/threat-snapshot/${scanId}`);
        
        if (!response.ok) {
          throw new Error('Failed to fetch report data');
        }
        
        const data = await response.json();
        setReportData(data);
      } catch (err) {
        setError(err.message);
        console.error('Error fetching report data:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchReportData();
  }, [scanId]);

  // Share functions
  const handleShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: `${reportData.company_name} - Cybersecurity Threat Snapshot`,
          text: `Security assessment showing ${formatCurrency(reportData.eal_ml_total)} in annual risk exposure`,
          url: window.location.href
        });
      } catch (err) {
        console.log('Error sharing:', err);
      }
    } else {
      // Fallback: copy link to clipboard
      navigator.clipboard.writeText(window.location.href);
      alert('Link copied to clipboard!');
    }
  };

  const handleDownload = async () => {
    try {
      const response = await fetch(`/api/reports/${scanId}/pdf`, { method: 'POST' });
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `${reportData.company_name}-threat-snapshot.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Error downloading PDF:', err);
    }
  };

  const handleEmail = async () => {
    try {
      await fetch(`/api/reports/${scanId}/email`, { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          reportType: 'threat_snapshot',
          recipientEmail: reportData.contact_email 
        })
      });
      alert('Report sent via email!');
    } catch (err) {
      console.error('Error sending email:', err);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading your security assessment...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-medium text-gray-900 mb-2">Error Loading Report</h2>
          <p className="text-gray-600">{error}</p>
        </div>
      </div>
    );
  }

  if (!reportData) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <p className="text-gray-600">No report data available</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 print:bg-white">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-8 py-8">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <h1 className="text-3xl font-light text-gray-900">Cybersecurity Threat Snapshot</h1>
              </div>
              <div className="flex items-center gap-6 text-sm text-gray-600">
                <div>
                  <span className="font-medium">{reportData.company_name}</span>
                  <span className="mx-2">•</span>
                  <span>{reportData.domain}</span>
                </div>
                <div>
                  <span className="mx-2">•</span>
                  <span>{formatDate(reportData.scan_date)}</span>
                </div>
              </div>
            </div>
            
            <div className="print:hidden">
              <ShareActions 
                scanId={scanId}
                onDownload={handleDownload}
                onEmail={handleEmail}
                onShare={handleShare}
              />
            </div>
          </div>
        </div>
      </header>

      {/* Financial Impact Hero Section */}
      <section className="max-w-7xl mx-auto px-8 py-12">
        <FinancialImpactHero data={reportData} />
      </section>

      {/* Secondary Metrics */}
      <section className="max-w-7xl mx-auto px-8 py-12">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <RiskScoreGauge score={reportData.overall_risk_score} />
          <SeverityDistribution data={reportData} />
          <CategoryBreakdown data={reportData.category_breakdown || []} />
        </div>
      </section>

      {/* Critical Findings Summary */}
      <section className="max-w-7xl mx-auto px-8 py-12">
        <FindingSummary findings={reportData.critical_findings} />
      </section>

      {/* Footer CTA */}
      <section className="max-w-7xl mx-auto px-8 py-12 print:hidden">
        <div className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-3xl p-12 text-white text-center">
          <h3 className="text-2xl font-light mb-4">Need Help Addressing These Risks?</h3>
          <p className="text-gray-300 mb-8 max-w-2xl mx-auto">
            This assessment identifies critical security gaps requiring immediate attention. Our detailed remediation guide provides step-by-step solutions.
          </p>
          <button className="px-8 py-4 bg-white text-gray-900 rounded-xl hover:bg-gray-100 transition-colors font-medium">
            Get Full Technical Report
          </button>
        </div>
      </section>
    </div>
  );
}
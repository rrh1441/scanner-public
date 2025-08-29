// Test Handlebars template rendering
import handlebars from 'handlebars';

// Register the exact helpers from the server
handlebars.registerHelper('format_currency', (amount) => {
    console.log('format_currency called with:', amount, typeof amount);
    if (!amount || isNaN(amount)) return '0';
    return new Intl.NumberFormat('en-US', {
        minimumFractionDigits: 0,
        maximumFractionDigits: 0
    }).format(amount);
});

handlebars.registerHelper('format_abbrev', (value) => {
    const n = Number(value) || 0;
    const abs = Math.abs(n);
    if (abs >= 1000000000) return Math.round(abs / 1000000000) + 'B';
    if (abs >= 1000000) return Math.round(abs / 1000000) + 'M';
    if (abs >= 1000) return Math.round(abs / 1000) + 'K';
    return n.toString();
});

// Test template  
const templateSource = `
EAL Summary:
Most Likely: $\{\{format_currency eal_summary.total_eal_ml\}\}
Abbreviated: $\{\{format_abbrev eal_summary.total_eal_ml\}\}
Raw value: \{\{eal_summary.total_eal_ml\}\}

\{\{#if eal_summary\}\}
EAL exists: YES
\{\{else\}\}
EAL exists: NO
\{\{/if\}\}
`;

const template = handlebars.compile(templateSource);

// Test data (same structure as debug output)
const testData = {
    eal_summary: {
        total_eal_low: 70000,
        total_eal_ml: 350000,
        total_eal_high: 1400000,
        cyber_total_ml: 350000,
        total_eal_daily: 959
    }
};

console.log('🧪 Testing Handlebars template rendering:');
console.log(template(testData));
// Debug EAL data flow
import { LocalStore } from './dist/core/localStore.js';

async function debugEAL() {
    const store = new LocalStore();
    const scanId = 'scan--6spSBRmFwdET5i_WqrzW';
    
    console.log('🔍 Testing EAL data flow for:', scanId);
    
    // Test the exact query used in report generation
    try {
        const ealSummaryResult = await store.query('SELECT * FROM scan_eal_summary WHERE scan_id = $1', [scanId]);
        const ealSummary = ealSummaryResult.rows[0] || null;
        
        console.log('\n📊 EAL Summary Result:');
        console.log('- Row count:', ealSummaryResult.rows.length);
        console.log('- ealSummary object:', ealSummary);
        
        if (ealSummary) {
            console.log('\n🔢 Individual field values:');
            console.log('- total_eal_low:', ealSummary.total_eal_low, typeof ealSummary.total_eal_low);
            console.log('- total_eal_ml:', ealSummary.total_eal_ml, typeof ealSummary.total_eal_ml);  
            console.log('- total_eal_high:', ealSummary.total_eal_high, typeof ealSummary.total_eal_high);
            
            console.log('\n🧪 Format currency test:');
            const format_currency = (amount) => {
                console.log('  - Input:', amount, typeof amount, 'isNaN:', isNaN(amount));
                if (!amount || isNaN(amount)) return '0';
                return new Intl.NumberFormat('en-US', {
                    minimumFractionDigits: 0,
                    maximumFractionDigits: 0
                }).format(amount);
            };
            
            console.log('  - total_eal_ml formatted:', format_currency(ealSummary.total_eal_ml));
            console.log('  - total_eal_high formatted:', format_currency(ealSummary.total_eal_high));
        }
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    } finally {
        await store.close();
    }
}

debugEAL().catch(console.error);
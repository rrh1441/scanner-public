#!/bin/bash

# Staggered launch of 55 Banyan companies
# 24 concurrent workers, batches of 3 with 1.05s delays to respect LeakCheck 3 RPS

domains=(
    "flexi-dent.hu"
    "eclipsepracticemanagementsoftware.com" 
    "webops.com"
    "hr4.com"
    "progress-plus.co.uk"
    "agilefleet.com"
    "star-trac.de"
    "codeoneportal.com"
    "burps.com.au"
    "intuitivesystems.com"
    "touchstream.media"
    "mosaiclearning.com"
    "hancocksoftware.com"
    "medtechglobal.com"
    "foxinsights.ai"
    "yourhere.ca"
    "asiweb.com"
    "americanbanksystems.com"
    "drttix.com"
    "geminishale.com"
    "fedeltapos.com"
    "dualenroll.com"
    "smartdocuments.com"
    "mallmaverick.com"
    "worldsmart.com.au"
    "hewssolutions.com"
    "snappic.com"
    "viostream.com"
    "softera.com"
    "software-answers.com"
    "subitup.com"
    "tecksoft.com"
    "versabadge.com"
    "promosuite.com"
    "intelligenz.com"
    "vividreports.com"
    "resolutionmd.com"
    "comtronicsystems.com"
    "futurenetpos.com"
    "thelakecompanies.com"
    "fxcubic.com"
    "goalline.ca"
    "trackmysolutions.com"
    "iconisoftware.com"
    "mobileidentify.com"
    "levltelematics.com"
    "immo-office.de"
    "rubensteintech.com"
    "sqbx.com"
    "campuscafesoftware.com"
    "hwcs.com"
    "linxio.com"
    "bequick.com"
    "softsmiths.com"
    "alpine-fire.com"
)

echo "🚀 Starting staggered launch of ${#domains[@]} Banyan companies..."
echo "📊 24 concurrent workers, batches of 3 with 1.05s delays"
echo "⏰ Start time: $(date)"
echo

batch_count=0
total_launched=0

for i in "${!domains[@]}"; do
    domain="${domains[$i]}"
    scan_id="banyan-$((i+1))-$(echo $domain | sed 's/\./-/g')"
    
    # Launch scan in background
    curl -X POST http://localhost:8080/scan \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"$domain\", \"scan_id\": \"$scan_id\"}" \
        --silent &
    
    total_launched=$((total_launched + 1))
    batch_count=$((batch_count + 1))
    
    echo "✅ Launched $total_launched/55: $domain"
    
    # Every 3 scans, add 1.05s delay (respects 3 RPS LeakCheck limit)
    if [ $((batch_count % 3)) -eq 0 ]; then
        echo "⏱️  Batch complete, waiting 1.05s for LeakCheck rate limit..."
        sleep 1.05
        batch_count=0
    fi
done

# Wait for all background jobs to complete
wait

echo
echo "🎯 All 55 scans launched!"
echo "⏰ End time: $(date)"
echo
echo "📊 Monitoring commands:"
echo "curl -s http://localhost:8080/health | jq '.queue'"
echo "psql scanner_local -c \"SELECT COUNT(*) as total, status FROM scans GROUP BY status;\""
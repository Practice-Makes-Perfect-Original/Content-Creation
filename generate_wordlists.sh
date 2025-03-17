#!/bin/bash

# Hardcoded wordlist paths
WORDLIST1="/usr/share/wordlists/ambtest_4.txt"
WORDLIST2="/usr/share/wordlists/ambtest_6.txt"
OUTPUT_FILE="final_wordlist.txt"

# Verify files exist
if [[ ! -f "$WORDLIST1" ]]; then
    echo "Error: Wordlist 1 not found: $WORDLIST1"
    exit 1
fi
if [[ ! -f "$WORDLIST2" ]]; then
    echo "Error: Wordlist 2 not found: $WORDLIST2"
    exit 1
fi

# Clear previous output file
> "$OUTPUT_FILE"

# Get total expected combinations
TOTAL_WORDS1=$(wc -l < "$WORDLIST1")
TOTAL_WORDS2=$(wc -l < "$WORDLIST2")
TOTAL_COMBINATIONS=$((TOTAL_WORDS1 * 1000 * TOTAL_WORDS2))

# Start time tracking
START_TIME=$(date +%s)

# Estimated speed (Zephyrus G14 NVMe SSD + Ryzen 9 7940HS)
EST_SPEED=500000  # Approx. 500K lines/sec on SSD
EST_TIME=$((TOTAL_COMBINATIONS / EST_SPEED))

echo "🚀 Generating wordlist (~$TOTAL_COMBINATIONS lines)..."
echo "⏳ Estimated time: ~$EST_TIME seconds (~$(($EST_TIME / 60)) minutes)."

# Initialize counter
COUNT=0

# Generate combinations correctly
while IFS= read -r word1; do
  for num in {000..999}; do
    while IFS= read -r word2; do
      echo "${word1}${num}${word2}" >> "$OUTPUT_FILE"
      ((COUNT++))

      # Show progress every 1,000,000 lines
      if (( COUNT % 1000000 == 0 )); then
        CURRENT_TIME=$(date +%s)
        ELAPSED_TIME=$((CURRENT_TIME - START_TIME))
        PERCENTAGE=$((COUNT * 100 / TOTAL_COMBINATIONS))
        echo "📊 Progress: $COUNT / $TOTAL_COMBINATIONS (~$PERCENTAGE%) - ⏳ Elapsed Time: $ELAPSED_TIME sec"
      fi
    done < "$WORDLIST2"
  done
done < "$WORDLIST1"

# End time tracking
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo "✅ Wordlist generation complete in $TOTAL_TIME seconds (~$(($TOTAL_TIME / 60)) minutes)!"
echo "📂 Saved to: $OUTPUT_FILE"


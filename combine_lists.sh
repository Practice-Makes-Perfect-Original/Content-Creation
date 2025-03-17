#!/bin/bash
OUTPUT_FILE="final_wordlist.txt"
> "$OUTPUT_FILE"  # Clear file before appending

for word1 in $(cat /usr/share/wordlists/ambtest_4.txt); do
  for num in {000..999}; do
    for word2 in $(cat /usr/share/wordlists/ambtest_6.txt); do
      echo "${word1}${num}${word2}" >> "$OUTPUT_FILE"
    done
  done
done

echo "Wordlist generated: $OUTPUT_FILE"

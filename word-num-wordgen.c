#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Define limits
#define MAX_WORDS 10000  // Adjust based on wordlist size
#define MAX_WORD_LEN 8
#define NUM_MAX 1000  // 0 to 999

// Function to count words in a file
int count_words(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening wordlist");
        exit(1);
    }
    
    int count = 0;
    char word[MAX_WORD_LEN + 1];
    while (fgets(word, sizeof(word), file)) {
        count++;
    }
    
    fclose(file);
    return count;
}

// Function to load words into an array
void load_words(const char *filename, char words[][MAX_WORD_LEN + 1], int max_words) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening wordlist");
        exit(1);
    }
    
    int i = 0;
    while (i < max_words && fgets(words[i], MAX_WORD_LEN + 1, file)) {
        words[i][strcspn(words[i], "\n")] = 0;  // Remove newline
        i++;
    }
    
    fclose(file);
}

// Function to calculate estimated file size
double estimate_size(int words1, int words2) {
    double entry_size = MAX_WORD_LEN + 3 + MAX_WORD_LEN + 2;  // Word + 3-digit num + word + newline
    double total_size = (double) words1 * NUM_MAX * words2 * entry_size;
    return total_size / (1024 * 1024 * 1024);  // Convert bytes to GB
}

int main() {
    char words1[MAX_WORDS][MAX_WORD_LEN + 1];
    char words2[MAX_WORDS][MAX_WORD_LEN + 1];

    printf("Enter first wordlist file path: ");
    char file1[100];
    scanf("%s", file1);
    
    printf("Enter second wordlist file path: ");
    char file2[100];
    scanf("%s", file2);

    // Load wordlists
    int count1 = count_words(file1);
    int count2 = count_words(file2);
    load_words(file1, words1, count1);
    load_words(file2, words2, count2);

    // Calculate estimated file size
    double est_size_gb = estimate_size(count1, count2);
    printf("\nEstimated password file size: %.2f GB\n", est_size_gb);
    
    // Ask user if they want to proceed
    char response;
    printf("Proceed with this size? (y/n): ");
    scanf(" %c", &response);
    
    // If user declines, let them enter a max file size
    double max_size_gb = est_size_gb;
    if (response == 'n' || response == 'N') {
        printf("Enter max file size in GB: ");
        scanf("%lf", &max_size_gb);
    }

    // Calculate number of lines allowed within the limit
    double entry_size = MAX_WORD_LEN + 3 + MAX_WORD_LEN + 2;
    long max_entries = (max_size_gb * 1024 * 1024 * 1024) / entry_size;

    // Open output file
    FILE *output = fopen("passwords.txt", "w");
    if (!output) {
        perror("Error creating password file");
        exit(1);
    }

    printf("\nGenerating passwords...\n");
    long count = 0;
    
    // Generate passwords
    for (int i = 0; i < count1 && count < max_entries; i++) {
        for (int num = 0; num < NUM_MAX && count < max_entries; num++) {
            for (int j = 0; j < count2 && count < max_entries; j++) {
                fprintf(output, "%s%03d%s\n", words1[i], num, words2[j]);
                count++;
            }
        }
    }
    
    fclose(output);
    printf("\nPassword list created: passwords.txt (%ld entries)\n", count);
    return 0;
}

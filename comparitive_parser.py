import re
import math
from collections import Counter
from datasketch import MinHash

def tokenize(text):
    return re.findall(r'\b\w+\b', text.lower())

def get_minhash(tokens, num_perm=128):
    m = MinHash(num_perm=num_perm)
    for token in tokens:
        m.update(token.encode('utf8'))
    return m

def jaccard_similarity(set1, set2):
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union else 0.0

def cosine_similarity(vec1, vec2):
    dot = sum(vec1[x] * vec2.get(x, 0) for x in vec1)
    mag1 = math.sqrt(sum(v ** 2 for v in vec1.values()))
    mag2 = math.sqrt(sum(v ** 2 for v in vec2.values()))
    return dot / (mag1 * mag2) if mag1 and mag2 else 0.0

def euclidean_distance(vec1, vec2):
    all_keys = set(vec1) | set(vec2)
    sum_sq = sum((vec1.get(k, 0) - vec2.get(k, 0)) ** 2 for k in all_keys)
    return math.sqrt(sum_sq)

def compare_files(file1_path, file2_path):
    try:
        with open(file1_path, 'r', encoding='utf-8') as f1, open(file2_path, 'r', encoding='utf-8') as f2:
            text1 = f1.read()
            text2 = f2.read()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return

    tokens1 = tokenize(text1)
    tokens2 = tokenize(text2)

    set1 = set(tokens1)
    set2 = set(tokens2)
    vec1 = Counter(tokens1)
    vec2 = Counter(tokens2)

    minhash1 = get_minhash(set1)
    minhash2 = get_minhash(set2)
    minhash_sim = minhash1.jaccard(minhash2)
    jaccard_sim = jaccard_similarity(set1, set2)
    cosine_sim = cosine_similarity(vec1, vec2)
    euclidean_dist = euclidean_distance(vec1, vec2)

    print(f"\nFile 1: {file1_path}")
    print(f"File 2: {file2_path}\n")

    print("Similarity Metrics:")
    print(f"MinHash (Approx. Jaccard):       {minhash_sim:.4f}")
    print(f"Jaccard (Exact set match):       {jaccard_sim:.4f}")
    print(f"Cosine (Token frequency angle):  {cosine_sim:.4f}")
    print(f"Euclidean Distance:              {euclidean_dist:.4f} (lower = more similar)")

if __name__ == "__main__":
    file1 = r"C:\Users\keato\OneDrive\Desktop\python\compare_1.txt"
    file2 = r"C:\Users\keato\OneDrive\Desktop\python\compare_2.txt"
    compare_files(file1, file2)

import numpy as np
import hashlib

class VideoAnalyzer:
    @staticmethod
    def analyze(video_bytes):
        """Analyze video for deepfake indicators"""
        sample = video_bytes[:16384]  # First 16KB
        
        if not sample:
            return {'score': 50, 'verdict': 'SUSPICIOUS', 'metadata': {}}
        
        # Byte entropy analysis (higher entropy = more random = likely real)
        byte_counts = np.bincount(np.frombuffer(sample, dtype=np.uint8), minlength=256)
        probs = byte_counts / len(sample)
        entropy = -np.sum(probs * np.log2(probs + 1e-10))
        max_entropy = 8.0
        normalized_entropy = entropy / max_entropy
        
        # Low entropy = more likely synthetic/deepfake
        deepfake_score = (1 - normalized_entropy) * 80
        
        # Check for compression artifacts
        zero_ratio = sample.count(0) / len(sample)
        compression_score = zero_ratio * 30 if zero_ratio > 0.3 else 0
        
        # Check for repeated patterns (AI generation artifacts)
        unique_bytes = len(set(sample)) / 256
        pattern_score = (1 - unique_bytes) * 30 if unique_bytes < 0.8 else 0
        
        # File size check
        size_mb = len(video_bytes) / (1024 * 1024)
        size_score = 0
        if size_mb < 0.1:  # Too small
            size_score = 25
        
        score = int(min(deepfake_score + compression_score + pattern_score + size_score, 100))
        verdict = "FRAUD" if score >= 75 else "SUSPICIOUS" if score >= 45 else "SAFE"
        
        # Deepfake indicator (0-1 scale)
        deepfake_indicator = round(deepfake_score / 100, 2)
        
        return {
            'score': score,
            'verdict': verdict,
            'deepfake_indicator': deepfake_indicator,
            'metadata': {
                'byte_entropy': round(entropy, 3),
                'unique_bytes_ratio': round(unique_bytes, 3),
                'size_mb': round(size_mb, 2),
                'compression_ratio': round(zero_ratio, 3)
            }
        }

video_analyzer = VideoAnalyzer()
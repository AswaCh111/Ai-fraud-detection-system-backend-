import cv2
import numpy as np
from PIL import Image
import io

class ImageAnalyzer:
    @staticmethod
    def analyze(image_bytes):
        """Analyze image for fraud/tampering"""
        try:
            img = Image.open(io.BytesIO(image_bytes))
            
            # Convert to grayscale for analysis
            img_gray = img.convert('L')
            img_array = np.array(img_gray)
            
            # Pixel variance analysis (higher variance = more suspicious)
            variance = float(np.var(img_array))
            variance_score = min(variance / 5000, 100) * 0.6
            
            # Edge detection using OpenCV
            try:
                edges = cv2.Canny(img_array, 100, 200)
                edge_density = np.sum(edges > 0) / edges.size
                edge_score = edge_density * 100 * 0.4
            except:
                edge_score = 0
            
            # File size anomaly (too small might indicate corruption)
            size_mb = len(image_bytes) / (1024 * 1024)
            size_score = 0
            if size_mb < 0.01:  # Less than 10KB
                size_score = 30
            elif size_mb > 10:  # More than 10MB
                size_score = 15
            
            # Combined score
            score = int(min(variance_score + edge_score + size_score, 100))
            verdict = "FRAUD" if score >= 75 else "SUSPICIOUS" if score >= 45 else "SAFE"
            
            return {
                'score': score,
                'verdict': verdict,
                'metadata': {
                    'pixel_variance': round(variance, 2),
                    'edge_density': round(edge_density, 3) if 'edge_density' in dir() else None,
                    'size_mb': round(size_mb, 2),
                    'dimensions': f"{img.width}x{img.height}"
                }
            }
        except Exception as e:
            return {
                'score': 50, 
                'verdict': 'SUSPICIOUS', 
                'metadata': {'error': str(e)}
            }

image_analyzer = ImageAnalyzer()
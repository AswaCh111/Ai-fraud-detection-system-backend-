import PyPDF2
import io
import re
from pathlib import Path

class DocumentAnalyzer:
    @staticmethod
    def analyze(file_bytes, filename):
        """Analyze document for forgery"""
        score = 20  # Base score
        metadata = {}
        
        if filename.endswith('.pdf'):
            try:
                pdf = PyPDF2.PdfReader(io.BytesIO(file_bytes))
                meta = pdf.metadata or {}
                
                # Check metadata presence
                if not meta.get('/Producer'):
                    score += 35
                    metadata['missing_producer'] = True
                if not meta.get('/Creator'):
                    score += 25
                    metadata['missing_creator'] = True
                if not meta.get('/Title'):
                    score += 10
                
                # Check for suspicious metadata strings
                for key, value in meta.items():
                    if value and any(term in str(value).lower() for term in ['fake', 'forged', 'edited', 'modified']):
                        score += 40
                        metadata['suspicious_metadata'] = True
                        break
                
                # Check page count anomalies
                if len(pdf.pages) == 0:
                    score += 50
                    metadata['empty_document'] = True
                elif len(pdf.pages) > 100:
                    score += 20
                    metadata['too_many_pages'] = len(pdf.pages)
                
                # Try to extract text, look for manipulation indicators
                try:
                    text = ""
                    for page in pdf.pages[:3]:
                        text += page.extract_text() or ""
                    
                    if 'this document has been altered' in text.lower():
                        score += 45
                    if 'forged' in text.lower() or 'tampered' in text.lower():
                        score += 35
                except:
                    pass
                    
            except Exception as e:
                score += 60  # Corrupted PDF
                metadata['error'] = str(e)
        
        elif filename.endswith(('.doc', '.docx')):
            # Basic DOCX/DOC check
            if b'modified' in file_bytes[:10000].lower():
                score += 25
            if len(file_bytes) < 1000:  # Too small
                score += 30
                metadata['file_too_small'] = True
        
        else:  # TXT files
            content = file_bytes[:5000].decode('utf-8', errors='ignore')
            suspicious_terms = ['forged', 'fake', 'tampered', 'edited', 'altered']
            if any(term in content.lower() for term in suspicious_terms):
                score += 40
        
        score = min(score, 100)
        verdict = "FRAUD" if score >= 75 else "SUSPICIOUS" if score >= 45 else "SAFE"
        
        return {
            'score': score,
            'verdict': verdict,
            'metadata': metadata
        }

document_analyzer = DocumentAnalyzer()
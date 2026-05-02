# export_service.py
import csv
import json
import io
import pandas as pd
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from openpyxl import Workbook

class ExportService:
    
    @staticmethod
    def export_to_csv(detections, filename=None):
        """Export detections to CSV"""
        if not filename:
            filename = f"fraudshield_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        headers = ['ID', 'Module', 'Verdict', 'Score', 'User', 'IPFS Hash', 'Created At']
        writer.writerow(headers)
        
        # Write data
        for d in detections:
            writer.writerow([
                d.get('id', ''),
                d.get('module', ''),
                d.get('verdict', ''),
                d.get('score', ''),
                d.get('user_email', ''),
                d.get('ipfs_hash', ''),
                d.get('created_at', '')
            ])
        
        return output.getvalue().encode('utf-8'), filename
    
    @staticmethod
    def export_to_excel(detections, stats, filename=None):
        """Export detections to Excel with multiple sheets"""
        if not filename:
            filename = f"fraudshield_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        
        output = io.BytesIO()
        
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Sheet 1: Detections
            df_detections = pd.DataFrame(detections)
            df_detections.to_excel(writer, sheet_name='Detections', index=False)
            
            # Sheet 2: Statistics
            df_stats = pd.DataFrame([stats])
            df_stats.to_excel(writer, sheet_name='Statistics', index=False)
            
            # Sheet 3: Summary by Module
            if detections:
                df_module = pd.DataFrame(detections).groupby('module').agg({
                    'score': 'mean',
                    'id': 'count'
                }).rename(columns={'id': 'count', 'score': 'avg_score'})
                df_module.to_excel(writer, sheet_name='Module Summary')
        
        return output.getvalue(), filename
    
    @staticmethod
    def export_to_json(detections, stats, filename=None):
        """Export detections to JSON"""
        if not filename:
            filename = f"fraudshield_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            'exported_at': datetime.now().isoformat(),
            'statistics': stats,
            'detections': detections
        }
        
        return json.dumps(export_data, indent=2).encode('utf-8'), filename

export_service = ExportService()
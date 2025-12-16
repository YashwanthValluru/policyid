#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, send_file
import os
import tempfile
import json
import time
from werkzeug.utils import secure_filename
from policy_matcher import PolicyMatcher
import csv
from io import StringIO

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = '/tmp/temp_uploads'

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize policy matcher
policy_matcher = PolicyMatcher()

# Simple in-memory counter for Vercel (resets on each deployment)
def get_next_download_number(dst_ip):
    """Get a unique download number based on timestamp and IP"""
    # Create a unique number based on current timestamp and IP
    timestamp = int(time.time() * 1000)  # milliseconds
    # Use last 3 digits of timestamp for uniqueness
    unique_num = timestamp % 1000
    # If it's 0, make it 1
    return unique_num if unique_num > 0 else 1

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_security_group():
    try:
        # Get destination IP
        dst_ip = request.form.get('dst_ip', '').strip()
        if not dst_ip:
            return jsonify({'error': 'Destination IP is required'}), 400
        
        # Get security group content (either from file upload or text area)
        sg_content = ''
        
        # Check if file was uploaded
        if 'sg_file' in request.files:
            file = request.files['sg_file']
            if file and file.filename:
                if not file.filename.lower().endswith('.csv'):
                    return jsonify({'error': 'Only CSV files are supported'}), 400
                
                # Read file content
                sg_content = file.read().decode('utf-8')
        
        # If no file, check text area
        if not sg_content:
            sg_content = request.form.get('sg_content', '').strip()
        
        if not sg_content:
            return jsonify({'error': 'Please provide security group data either by uploading a file or pasting content'}), 400
        
        # Validate CSV format
        try:
            csv_reader = csv.DictReader(StringIO(sg_content))
            fieldnames = csv_reader.fieldnames
            if not fieldnames or 'cidr_ipv4' not in fieldnames:
                return jsonify({'error': 'Invalid CSV format. Required columns not found.'}), 400
        except Exception as e:
            return jsonify({'error': f'Invalid CSV format: {str(e)}'}), 400
        
        # Process the security group content
        updated_content, matches_found, log_messages = policy_matcher.process_security_group_content(sg_content, dst_ip)
        
        return jsonify({
            'success': True,
            'updated_content': updated_content,
            'matches_found': matches_found,
            'log_messages': log_messages,
            'dst_ip': dst_ip
        })
        
    except Exception as e:
        return jsonify({'error': f'Processing error: {str(e)}'}), 500

@app.route('/download', methods=['POST'])
def download_updated_file():
    try:
        data = request.get_json()
        updated_content = data.get('updated_content', '')
        dst_ip = data.get('dst_ip', 'unknown')
        
        if not updated_content:
            return jsonify({'error': 'No content to download'}), 400
        
        # Get next download number
        download_number = get_next_download_number(dst_ip)
        
        # Create filename: destinationip-number.csv
        download_filename = f"{dst_ip}-{download_number}.csv"
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        temp_file.write(updated_content)
        temp_file.close()
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=download_filename,
            mimetype='text/csv'
        )
        
    except Exception as e:
        return jsonify({'error': f'Download error: {str(e)}'}), 500

@app.route('/list_policy_files')
def list_policy_files():
    """List available policy files"""
    try:
        policy_files = []
        policy_dir = 'POLICY_ID'
        
        if os.path.exists(policy_dir):
            for filename in os.listdir(policy_dir):
                if filename.endswith('_ads.csv') or filename.endswith('_ads.xlsx'):
                    # Extract IP from filename
                    ip = filename.replace('_ads.csv', '').replace('_ads.xlsx', '')
                    file_type = 'CSV' if filename.endswith('.csv') else 'XLSX'
                    policy_files.append({
                        'ip': ip,
                        'filename': filename,
                        'type': file_type,
                        'supported': True  # Both CSV and XLSX are supported
                    })
        
        return jsonify({'policy_files': policy_files})
        
    except Exception as e:
        return jsonify({'error': f'Error listing policy files: {str(e)}'}), 500

# For Vercel deployment
if __name__ == '__main__':
    # Local development
    app.run(debug=True, host='0.0.0.0', port=5111)
else:
    # Production (Vercel)
    app.config['DEBUG'] = False
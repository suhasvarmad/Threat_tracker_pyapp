# In bulk_processor.py
import os
from pathlib import Path
from processor.main import process_log

# Define the input and output directories
DATA_DIR = 'data'
OUTPUT_DIR = 'output'

def main():
    """
    Scans the DATA_DIR, processes each log file, and saves the result
    to the OUTPUT_DIR.
    """
    print(f"Starting bulk processing of files in '{DATA_DIR}' directory...")
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    log_files = list(Path(DATA_DIR).glob('*.json'))
    
    if not log_files:
        print(f"No .json files found in '{DATA_DIR}'. Please add sample log files.")
        return

    for log_file_path in log_files:
        filename = log_file_path.name
        print(f"\n--- Processing file: {filename} ---")
        
        vendor = filename.split('_')[0]
        
        if vendor not in ['wazuh', 'sentinelone', 'elastic']:
            print(f"Warning: Could not determine vendor from filename '{filename}'. Skipping.")
            continue
            
        raw_log_content = log_file_path.read_text()
        
        unified_log_json = process_log(raw_log_content, vendor)
        
        # NEW: Check if processing was successful before saving
        if unified_log_json:
            output_filename = f"{log_file_path.stem}_unified.json"
            output_path = Path(OUTPUT_DIR) / output_filename
            
            output_path.write_text(unified_log_json)
            print(f"Successfully saved unified log to: {output_path}")
        else:
            # This will execute if process_log returned None due to an error
            print(f"Skipping file '{filename}' due to a processing error.")

if __name__ == '__main__':
    main()
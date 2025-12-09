import os
import json
import csv
from datetime import datetime

def write_run_json(run_id, data):
    """Write run results to JSON file"""
    os.makedirs("results/runs", exist_ok=True)
    filepath = f"results/runs/{run_id}.json"
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    
    return filepath

def append_csv(data):
    """Append results to CSV file"""
    os.makedirs("results/reports", exist_ok=True)
    filepath = "results/reports/all_results.csv"
    
    if not data:
        return filepath
    
    # Determine if file exists
    file_exists = os.path.exists(filepath)
    
    # Get fieldnames - use existing headers if file exists, otherwise from first record
    if file_exists and os.path.getsize(filepath) > 0:
        with open(filepath, 'r', newline='') as rf:
            reader = csv.DictReader(rf)
            existing_fieldnames = reader.fieldnames
            # Combine existing and new fields
            new_fields = set()
            for row in data:
                new_fields.update(row.keys())
            fieldnames = list(existing_fieldnames) if existing_fieldnames else list(data[0].keys())
            # Add any new fields that weren't in the original
            for field in new_fields:
                if field not in fieldnames:
                    fieldnames.append(field)
    else:
        fieldnames = list(data[0].keys())
    
    with open(filepath, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        
        if not file_exists or os.path.getsize(filepath) == 0:
            writer.writeheader()
        
        for row in data:
            writer.writerow(row)
    
    return filepath
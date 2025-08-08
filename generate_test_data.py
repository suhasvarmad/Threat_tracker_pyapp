# In generate_test_data.py
import json
import os
import uuid
from pathlib import Path

DATA_DIR = 'data'
# The original sample files we will use as templates
TEMPLATES = [
    'elastic_sample1.json',
    'sentinelone_sample1.json',
    'wazuh_sample1.json'
]
NUM_COPIES = 33

def generate_logs():
    """Generates multiple log files based on templates."""
    print("Generating test log files...")

    for template_name in TEMPLATES:
        template_path = Path(DATA_DIR) / template_name
        if not template_path.exists():
            print(f"Warning: Template file '{template_path}' not found. Skipping.")
            continue

        # Load the template content
        content = template_path.read_text()
        data = json.loads(content)
        vendor = template_name.split('_')[0]

        # Create copies
        for i in range(2, NUM_COPIES + 2): # Start from _sample2.json
            # Make each log slightly unique by changing its ID
            if vendor == 'elastic':
                data['_id'] = str(uuid.uuid4())
            elif vendor == 'sentinelone':
                if 'event' in data:
                    data['event']['id'] = str(uuid.uuid4())

            new_filename = f"{vendor}_sample{i}.json"
            new_filepath = Path(DATA_DIR) / new_filename

            # Write the new file
            new_filepath.write_text(json.dumps(data, indent=2))

    print(f"Done! Created {len(TEMPLATES) * NUM_COPIES} new log files in the '{DATA_DIR}' folder.")

if __name__ == '__main__':
    generate_logs()
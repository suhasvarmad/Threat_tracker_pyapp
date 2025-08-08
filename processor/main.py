# In processor/main.py
import json
from typing import Optional
from .fast_mapper import fast_path_mapper
from .llm_enricher import enrich_log_with_llm

def process_log(raw_log_str: str, vendor: str) -> Optional[str]:
    """
    Full pipeline for processing a single log.
    Returns the unified JSON string, or None if an error occurs.
    """
    try:
        raw_log_dict = json.loads(raw_log_str)
        
        # Step 1: Fast path mapping
        print(f"[{vendor.upper()}] Running fast mapper...")
        partially_mapped_log = fast_path_mapper(raw_log_dict, vendor)
        
        # Step 2: LLM enrichment path
        print(f"[{vendor.upper()}] Running LLM enrichment...")
        fully_mapped_log = enrich_log_with_llm(partially_mapped_log)
        
        # Step 3: Return the final result
        return fully_mapped_log.model_dump_json(indent=2, exclude_none=True)

    except Exception as e:
        # NEW: Catch any error during processing, print it, and return None
        print(f"!!! ERROR processing log for vendor '{vendor}': {e}")
        return None


if __name__ == '__main__':
    # This test block remains the same for single-file testing.
    with open('data/elastic_test_log.json', 'r') as f:
        sample_elastic_log = f.read()
    
    print("\n--- PROCESSING ELASTIC LOG ---")
    final_log_json = process_log(sample_elastic_log, vendor='elastic')
    
    if final_log_json:
        print("\n--- FINAL UNIFIED LOG ---")
        print(final_log_json)
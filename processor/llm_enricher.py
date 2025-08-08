# In processor/llm_enricher.py
import os
from typing import Optional # <--- ADD THIS LINE
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field # <--- UPDATE THIS LINE

from .schemas import EnrichedUnifiedLog
load_dotenv() # Loads all keys from your .env file

# ... (The LogEnrichment class remains the same) ...
class LogEnrichment(BaseModel):
    event_category: str = Field(description="...")
    primary_tactic: Optional[str] = Field(None, description="...")
    primary_technique: Optional[str] = Field(None, description="...")


# --- Initialize the LLM ---
# This now points to Google's Gemini model
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash-latest", temperature=0)


prompt = ChatPromptTemplate.from_template(
    """
    You are an expert security log analyst. Your task is to analyze a raw log event and extract structured information based on its description.
    
    Based on the following event description, please provide the inferred details.
    
    **Event Description:**
    {event_description}
    
    **Full Raw Log (for context):**
    {full_log}
    """
)

enrichment_chain = prompt | llm.with_structured_output(LogEnrichment)

def enrich_log_with_llm(log_object: EnrichedUnifiedLog) -> EnrichedUnifiedLog:
    """Takes a partially mapped log and uses an LLM to fill in complex fields."""
    if not log_object.event.description:
        return log_object

    try:
        enrichment_data = enrichment_chain.invoke({
            "event_description": log_object.event.description,
            "full_log": log_object.event.fullLog
        })
        
        # --- Merge the LLM's output back into our main object ---
        if enrichment_data:
            log_object.event.category = enrichment_data.event_category
            # Only add tactic/technique if not already present from direct mapping
            if not log_object.tactic and enrichment_data.primary_tactic:
                log_object.tactic = enrichment_data.primary_tactic
            if not log_object.technique and enrichment_data.primary_technique:
                log_object.technique = enrichment_data.primary_technique
            
    except Exception as e:
        print(f"Error during LLM enrichment: {e}")
        if not log_object.tags:
            log_object.tags = []
        log_object.tags.append('enrichment_failed')
    
    return log_object
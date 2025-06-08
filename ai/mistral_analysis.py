import threading
import ollama
from utils.logger import log_event

_lock = threading.Lock()

def analyze_text(prompt: str) -> str:
    try:
        full_prompt = (
            "You are a security monitoring AI. Analyze the following input for dangerous behavior, "
            "explain why, and suggest mitigation:\n\n" + prompt
        )

        with _lock:
            response = ollama.chat(
                model="mistral",  # make sure this is your pulled model name
                messages=[
                    {"role": "user", "content": full_prompt}
                ]
            )

        return response['message']['content'].strip()

    except Exception as e:
        log_event("AI_ERROR", f"Exception in analyze_text via Ollama: {str(e)}")
        raise

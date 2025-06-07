import threading
import ollama
from utils.logger import log_event

_lock = threading.Lock()

def analyze_text(prompt: str) -> str:
    try:
        full_prompt = (
                "You are a Windows system monitoring AI. Only flag truly dangerous or malicious changes. If the input is safe, clearly say so and do not raise any alert."
                + prompt
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

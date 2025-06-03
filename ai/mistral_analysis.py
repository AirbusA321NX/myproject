import threading
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
from utils.logger import log_event

_MODEL_NAME = "mistral-ai/mistral-3.1-small"
_tokenizer = None
_model = None
_pipeline = None
_lock = threading.Lock()

def _load_model():
    global _tokenizer, _model, _pipeline
    with _lock:
        if _pipeline is None:
            _tokenizer = AutoTokenizer.from_pretrained(_MODEL_NAME)
            _model = AutoModelForCausalLM.from_pretrained(
                _MODEL_NAME,
                torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
            )
            if torch.cuda.is_available():
                _model.to("cuda")
            _pipeline = pipeline(
                "text-generation",
                model=_model,
                tokenizer=_tokenizer,
                device=0 if torch.cuda.is_available() else -1,
            )
    print(f"_pipeline loaded, type: {type(_pipeline)}")  # <-- add this
def analyze_text(prompt: str) -> str:
    global _pipeline
    try:
        with _lock:
            if _pipeline is None:
                _load_model()
        print(f"Using _pipeline of type {type(_pipeline)}")  # debug line
        full_prompt = (
            "You are a security monitoring AI. Analyze the following input for dangerous behavior, explain why, and suggest mitigation:\n\n"
            + prompt
        )
        result = _pipeline(full_prompt, max_new_tokens=128, do_sample=False)[0]["generated_text"]
        return result[len(full_prompt):].strip()
    except Exception as e:
        log_event("AI_ERROR", f"Exception in analyze_text: {str(e)}")
        raise



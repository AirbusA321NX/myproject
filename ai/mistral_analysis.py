import threading
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
from utils.logger import log_event

_MODEL_NAME = "mistral-ai/mistral-3.1-small"
_tokenizer = None
_model = None
_pipeline = None
_lock = threading.Lock()
_loaded = False  # Track loading state separately


def _load_model():
    global _tokenizer, _model, _pipeline, _loaded
    if not _loaded:  # Ensure we only load once
        try:
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
            _loaded = True
        except Exception as e:
            log_event("MODEL_LOAD_ERROR", f"Failed to load model: {str(e)}")
            raise


def analyze_text(prompt: str) -> str:
    try:
        # Ensure model is loaded safely
        with _lock:
            if not _loaded:
                _load_model()

        # Create local reference while holding lock
        local_pipeline = _pipeline

        # Verify pipeline is valid
        if local_pipeline is None:
            raise RuntimeError("Pipeline initialization failed")

        # Generate prompt
        full_prompt = (
                "You are a security monitoring AI. Analyze the following input for dangerous behavior, "
                "explain why, and suggest mitigation:\n\n" + prompt
        )

        # Process request
        results = local_pipeline(
            full_prompt,
            max_new_tokens=128,
            do_sample=False,
            pad_token_id=local_pipeline.tokenizer.eos_token_id  # Ensure proper termination
        )

        # Extract and clean response
        generated_text = results[0]["generated_text"]
        return generated_text[len(full_prompt):].strip()

    except Exception as e:
        log_event("AI_ERROR", f"Exception in analyze_text: {str(e)}")
        raise
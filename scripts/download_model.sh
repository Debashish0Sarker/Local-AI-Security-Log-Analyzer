#!/usr/bin/env sh
set -e
MODEL_FILE="${MODEL_FILE:-Qwen3.5-2B-Q4_K_M.gguf}"
mkdir -p models
[ -f "models/$MODEL_FILE" ] && { echo "already present"; exit 0; }
curl -L --fail -o "models/$MODEL_FILE.part" "https://huggingface.co/unsloth/Qwen3.5-2B-GGUF/resolve/main/$MODEL_FILE"
mv "models/$MODEL_FILE.part" "models/$MODEL_FILE"
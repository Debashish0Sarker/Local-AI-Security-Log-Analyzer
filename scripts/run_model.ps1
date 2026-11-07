param([string]$Model = "models\Qwen3.5-2B-Q4_K_M.gguf")
llama-server -m $Model -c 2048 -np 1 -t 2 -ngl 0 --jinja --host 127.0.0.1 --port 8080
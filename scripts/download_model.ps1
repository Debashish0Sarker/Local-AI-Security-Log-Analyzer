param([string]$ModelFile = "Qwen3.5-2B-Q4_K_M.gguf", [string]$Repo = "unsloth/Qwen3.5-2B-GGUF")
New-Item -ItemType Directory -Force -Path models | Out-Null
$dest = Join-Path "models" $ModelFile
if (Test-Path $dest) { Write-Host "$dest already present"; exit 0 }
curl.exe -L -o "$dest.part" "https://huggingface.co/$Repo/resolve/main/$ModelFile"
Move-Item "$dest.part" $dest
Write-Host "saved $dest"
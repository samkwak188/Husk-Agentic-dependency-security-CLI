#!/bin/bash
set -euo pipefail

echo "Husk Setup - Cloning ground truth datasets..."

if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi
mkdir -p datasets

if [ ! -d "datasets/datadog/.git" ]; then
  git clone --depth 1 https://github.com/DataDog/malicious-software-packages-dataset.git datasets/datadog
else
  echo "DataDog dataset already present."
fi

if [ ! -d "datasets/backstabbers/.git" ]; then
  git clone --depth 1 https://github.com/dasfreak/Backstabbers-Knife-Collection.git datasets/backstabbers
else
  echo "Backstabber's dataset already present."
fi

if command -v docker >/dev/null 2>&1; then
  echo "Building sandbox image..."
  docker build -t husk-sandbox -f docker/Dockerfile.sandbox .
else
  echo "Docker not found. Skipping sandbox image build."
fi

echo "Preparing local test fixture directories..."
mkdir -p test/fixtures/malicious test/fixtures/benign test-output

AI_PROVIDER="${AI_PROVIDER:-auto}"

if [ "$AI_PROVIDER" = "openrouter" ] && [ -n "${OPENROUTER_API_KEY:-}" ]; then
  echo "OPENROUTER_API_KEY detected. OpenRouter workflow is enabled."
elif [ "$AI_PROVIDER" = "openai" ] && [ -n "${OPENAI_API_KEY:-}" ]; then
  echo "OPENAI_API_KEY detected. OpenAI Responses workflow is enabled."
elif [ "$AI_PROVIDER" = "openrouter" ]; then
  echo "AI_PROVIDER=openrouter but OPENROUTER_API_KEY is not set. Husk will run in deterministic fallback mode."
elif [ "$AI_PROVIDER" = "openai" ]; then
  echo "AI_PROVIDER=openai but OPENAI_API_KEY is not set. Husk will run in deterministic fallback mode."
elif [ -n "${OPENAI_API_KEY:-}" ]; then
  echo "OPENAI_API_KEY detected. Husk will default to the OpenAI workflow."
elif [ -n "${OPENROUTER_API_KEY:-}" ]; then
  echo "OPENROUTER_API_KEY detected. Husk will default to the OpenRouter workflow."
else
  echo "No AI provider key is set. Husk will run in deterministic fallback mode."
fi

echo "Setup complete. Run 'npm run scan -- <package>' to start."

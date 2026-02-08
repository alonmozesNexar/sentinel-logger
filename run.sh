#!/bin/bash
# Sentinel Logger Startup Script
# Loads environment variables and starts the Flask server

cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate

# Load API keys from shell profile if not already set
if [ -z "$ANTHROPIC_API_KEY" ]; then
    # Try to load from common shell profiles
    [ -f ~/.zshrc ] && source ~/.zshrc 2>/dev/null
    [ -f ~/.bashrc ] && source ~/.bashrc 2>/dev/null
    [ -f ~/.bash_profile ] && source ~/.bash_profile 2>/dev/null
fi

# Export the API key so Python subprocess can see it
export ANTHROPIC_API_KEY
export OPENAI_API_KEY

# Check if Claude API key is available
if [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "Claude API key detected"
else
    echo "Warning: ANTHROPIC_API_KEY not set. AI features will be limited."
fi

# Check if OpenAI API key is available
if [ -n "$OPENAI_API_KEY" ]; then
    echo "OpenAI API key detected"
fi

# Start the server
echo ""
echo "Starting Sentinel Logger..."
echo ""
python main.py

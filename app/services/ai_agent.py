"""
AI Agent Service for Deep Log Analysis
Ensemble mode: Uses multiple AI providers for reliable analysis
"""
import os
import requests
import concurrent.futures
from typing import Optional, Dict, List


class AIAgent:
    """
    AI-powered log analysis agent using multiple providers for reliability.
    Supports: Ollama (local), OpenAI, Anthropic Claude
    """

    SYSTEM_PROMPT = """You are a helpful assistant for QA testers who may NOT be familiar with camera firmware or embedded systems. Your job is to:
1. Find problems in the log
2. Explain them in SIMPLE terms
3. Help create bug reports

## YOUR AUDIENCE
- QA testers who may be new to this
- They don't know what "sd_erase_loop" or "soft_reset" means
- They need clear, actionable information to report bugs

## HOW TO EXPLAIN ISSUES

For EVERY issue found, use this format:

### 🔴 ISSUE: [Simple title like "Camera Keeps Restarting"]

**What happened:**
[1-2 sentences in plain English. Example: "The camera restarted unexpectedly 322 times."]

**Log evidence (copy this to bug report):**
```
Line 45: sd_erase_loop: 322
Line 12: wakeup_source: 0x80(soft_reset)
```

**Why this is a problem:**
[Simple explanation. Example: "Users will lose video recordings when the camera restarts."]

**Severity:** 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW

**Bug report title suggestion:**
"[Component] - [Problem] - [Impact]"
Example: "Camera - Unexpected restart loop - Video recordings lost"

---

## THINGS TO LOOK FOR (explain in simple terms)

1. **Restarts/Reboots** - Camera turned off and on unexpectedly
   - Look for: `soft_reset`, `reboot`, `panic`, `watchdog`
   - Plain English: "The camera crashed and restarted"

2. **Storage Problems** - Issues with memory card or internal storage
   - Look for: `sd_erase_loop`, `mount failed`, `I/O error`
   - Plain English: "The camera can't save videos properly"

3. **Recording Failures** - Video/audio not working
   - Look for: `encoder error`, `stream failed`, `recording stopped`
   - Plain English: "The camera stopped recording"

4. **Connection Issues** - WiFi, cloud, or phone app problems
   - Look for: `connection failed`, `timeout`, `network error`
   - Plain English: "The camera lost connection"

5. **Security Errors** - Authentication or verification failed
   - Look for: `token integrity`, `authentication failed`, `certificate`
   - Plain English: "The camera couldn't verify itself"

## OUTPUT STRUCTURE

Start with:
### 📊 SUMMARY
- Total issues found: X
- Critical: X | High: X | Medium: X | Low: X
- Main problem: [One sentence summary]

Then list each issue using the format above.

End with:
### 📝 RECOMMENDED BUG REPORTS
List the bugs that should be filed, with suggested titles.

## RULES
1. ALWAYS include the exact log lines - QA needs these for bug reports
2. ALWAYS explain in simple terms - assume no technical knowledge
3. ALWAYS suggest bug report titles
4. Use emojis for severity: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW
5. If log is incomplete or you can't find issues, say so clearly"""

    def __init__(self):
        self.ollama_url = "http://localhost:11434"
        self.ollama_model = "llama3.1:8b"  # Upgraded from llama3.2 for better analysis
        self.conversations = {}

        # Provider priority order (Gemini first as preferred)
        self.provider_priority = ['gemini', 'anthropic', 'openai', 'groq', 'ollama']

        # Initialize providers
        self.providers = {}
        self._init_providers()

    def _init_providers(self):
        """Initialize all available AI providers. Claude is prioritized."""
        # Anthropic Claude (PREFERRED - Best for log analysis)
        anthropic_key = os.environ.get('ANTHROPIC_API_KEY')
        if anthropic_key:
            self.providers['anthropic'] = {
                'name': 'Claude (Sonnet)',
                'type': 'anthropic',
                'api_key': anthropic_key,
                'available': True,
                'priority': 1  # Highest priority
            }

        # OpenAI
        openai_key = os.environ.get('OPENAI_API_KEY')
        if openai_key:
            self.providers['openai'] = {
                'name': 'OpenAI GPT-4',
                'type': 'openai',
                'api_key': openai_key,
                'available': True,
                'priority': 2
            }

        # Google Gemini (PRIMARY - FREE!)
        google_key = os.environ.get('GOOGLE_API_KEY')
        if google_key:
            self.providers['gemini'] = {
                'name': 'Gemini',
                'type': 'gemini',
                'api_key': google_key,
                'available': True,
                'priority': 1  # Highest priority
            }

        # Groq - DISABLED (using Gemini only)
        # groq_key = os.environ.get('GROQ_API_KEY')
        # if groq_key:
        #     self.providers['groq'] = {
        #         'name': 'Groq',
        #         'type': 'groq',
        #         'api_key': groq_key,
        #         'available': True,
        #         'priority': 4
        #     }

        # Ollama - DISABLED (using Gemini only)
        # if self._check_ollama():
        #     self.providers['ollama'] = {
        #         'name': 'Ollama (llama3.1:8b)',
        #         'type': 'ollama',
        #         'available': True,
        #         'priority': 5  # Lowest priority - local fallback
        #     }

    def _check_ollama(self) -> bool:
        """Check if Ollama is running."""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=2)
            return response.status_code == 200
        except (requests.RequestException, ConnectionError, OSError):
            return False

    def is_available(self) -> bool:
        return len(self.providers) > 0

    def get_conversation(self, session_id: str) -> list:
        if session_id not in self.conversations:
            self.conversations[session_id] = []
        return self.conversations[session_id]

    def clear_conversation(self, session_id: str):
        if session_id in self.conversations:
            del self.conversations[session_id]

    def _prepare_log_context(self, log_entries: list, max_entries: int = 200) -> str:
        """Prepare log entries for AI analysis with full technical details."""
        if not log_entries:
            return "No log entries provided."

        errors, warnings, info = [], [], []
        for entry in log_entries:
            level = entry.get('level', '').upper()
            if level in ('ERROR', 'CRITICAL', 'FATAL'):
                errors.append(entry)
            elif level in ('WARNING', 'WARN'):
                warnings.append(entry)
            else:
                info.append(entry)

        # Prioritize ALL errors and warnings, then add info for context
        context_entries = []
        context_entries.extend(errors)  # Include ALL errors
        context_entries.extend(warnings)  # Include ALL warnings
        remaining = max_entries - len(context_entries)
        if remaining > 0:
            context_entries.extend(info[:remaining])
        context_entries.sort(key=lambda x: x.get('line_number', 0))

        # Build detailed log context
        lines = []
        lines.append("=" * 60)
        lines.append(f"LOG ENTRIES ({len(errors)} errors, {len(warnings)} warnings)")
        lines.append("=" * 60)

        for entry in context_entries[:max_entries]:
            line_num = entry.get('line_number', '?')
            level = entry.get('level', 'INFO')
            # Get raw content - this is the original log line
            raw_content = entry.get('raw_content', entry.get('content', entry.get('message', '')))

            # Format: Show line number and the RAW log content
            lines.append(f"Line {line_num}: {raw_content[:600]}")

        lines.append("=" * 60)
        return "\n".join(lines)

    def _call_ollama(self, prompt: str) -> str:
        """Call Ollama API."""
        response = requests.post(
            f"{self.ollama_url}/api/generate",
            json={
                "model": self.ollama_model,
                "prompt": prompt,
                "system": self.SYSTEM_PROMPT,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "num_predict": 2000
                }
            },
            timeout=180
        )
        if response.status_code == 200:
            return response.json().get("response", "No response")
        raise Exception(f"Ollama error: {response.status_code}")

    def _call_openai(self, prompt: str, api_key: str) -> str:
        """Call OpenAI API."""
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.7,
                "max_tokens": 2000
            },
            timeout=60
        )
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        raise Exception(f"OpenAI error: {response.status_code} - {response.text}")

    def _call_anthropic(self, prompt: str, api_key: str) -> str:
        """Call Anthropic Claude API - using Claude 3.5 Sonnet for best results."""
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json={
                "model": "claude-sonnet-4-20250514",  # Claude Sonnet 4 - best for analysis
                "max_tokens": 4096,  # Increased for detailed analysis
                "system": self.SYSTEM_PROMPT,
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=120  # Increased timeout for thorough analysis
        )
        if response.status_code == 200:
            return response.json()["content"][0]["text"]
        raise Exception(f"Anthropic error: {response.status_code} - {response.text}")

    def _call_gemini(self, prompt: str, api_key: str) -> str:
        """Call Google Gemini API (FREE!)."""
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [
                    {"parts": [{"text": f"{self.SYSTEM_PROMPT}\n\n{prompt}"}]}
                ],
                "generationConfig": {
                    "temperature": 0.7,
                    "maxOutputTokens": 2000
                }
            },
            timeout=60
        )
        if response.status_code == 200:
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        raise Exception(f"Gemini error: {response.status_code} - {response.text}")

    def _call_groq(self, prompt: str, api_key: str) -> str:
        """Call Groq API (FREE! Very fast)."""
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.7,
                "max_tokens": 2000
            },
            timeout=60
        )
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        raise Exception(f"Groq error: {response.status_code} - {response.text}")

    def _call_provider(self, provider_id: str, prompt: str) -> Dict:
        """Call a single provider and return result."""
        provider = self.providers.get(provider_id)
        if not provider:
            return {'success': False, 'error': 'Provider not found'}

        try:
            if provider['type'] == 'ollama':
                response = self._call_ollama(prompt)
            elif provider['type'] == 'openai':
                response = self._call_openai(prompt, provider['api_key'])
            elif provider['type'] == 'anthropic':
                response = self._call_anthropic(prompt, provider['api_key'])
            elif provider['type'] == 'gemini':
                response = self._call_gemini(prompt, provider['api_key'])
            elif provider['type'] == 'groq':
                response = self._call_groq(prompt, provider['api_key'])
            else:
                return {'success': False, 'error': 'Unknown provider type'}

            return {
                'success': True,
                'response': response,
                'provider': provider['name']
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'provider': provider['name']
            }

    def _ensemble_analyze(self, prompt: str, use_single_provider: bool = True) -> Dict:
        """
        Run analysis using AI providers.

        By default, uses only the highest-priority available provider (Claude preferred).
        Set use_single_provider=False to run all providers in parallel (ensemble mode).
        """
        errors = []

        if use_single_provider:
            # Use priority-based selection - try providers in order until one succeeds
            sorted_providers = sorted(
                self.providers.items(),
                key=lambda x: x[1].get('priority', 99)
            )

            for provider_id, provider_info in sorted_providers:
                if not provider_info.get('available', True):
                    continue

                result = self._call_provider(provider_id, prompt)
                if result['success']:
                    return {
                        'success': True,
                        'analysis': result['response'],
                        'providers_used': [result['provider']],
                        'provider_count': 1,
                        'errors': errors if errors else None
                    }
                else:
                    errors.append(f"{result.get('provider', provider_id)}: {result['error']}")

            return {
                'success': False,
                'error': 'All providers failed: ' + '; '.join(errors)
            }

        # Ensemble mode - run all providers in parallel
        results = []
        successful_responses = []
        providers_used = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_provider = {
                executor.submit(self._call_provider, pid, prompt): pid
                for pid in self.providers.keys()
            }

            for future in concurrent.futures.as_completed(future_to_provider):
                provider_id = future_to_provider[future]
                try:
                    result = future.result()
                    results.append(result)
                    if result['success']:
                        successful_responses.append(result['response'])
                        providers_used.append(result['provider'])
                    else:
                        errors.append(f"{result.get('provider', provider_id)}: {result['error']}")
                except Exception as e:
                    errors.append(f"{provider_id}: {str(e)}")

        if not successful_responses:
            return {
                'success': False,
                'error': 'All providers failed: ' + '; '.join(errors)
            }

        # If multiple responses, combine them
        if len(successful_responses) == 1:
            combined = successful_responses[0]
        else:
            # Create a combined analysis from multiple providers
            combined = self._combine_responses(successful_responses, providers_used)

        return {
            'success': True,
            'analysis': combined,
            'providers_used': providers_used,
            'provider_count': len(providers_used),
            'errors': errors if errors else None
        }

    def _combine_responses(self, responses: List[str], providers: List[str]) -> str:
        """Combine multiple AI responses into one comprehensive analysis."""
        if len(responses) == 1:
            return responses[0]

        # Build combined response
        combined = "## Combined AI Analysis\n\n"
        combined += f"*Analysis from {len(responses)} AI engines: {', '.join(providers)}*\n\n"
        combined += "---\n\n"

        for i, (response, provider) in enumerate(zip(responses, providers), 1):
            combined += f"### Analysis {i} ({provider})\n\n"
            combined += response
            combined += "\n\n---\n\n"

        return combined

    def analyze(
        self,
        query: str,
        log_entries: list,
        session_id: str,
        quick_search_results: Optional[dict] = None
    ) -> dict:
        """Perform AI analysis on log entries using ensemble mode."""
        if not self.is_available():
            return {
                'success': False,
                'error': 'No AI providers available. Start Ollama or set API keys.'
            }

        log_context = self._prepare_log_context(log_entries)

        # Build prompt
        prompt = f"User Query: {query}\n\nLog Entries:\n{log_context}"

        # Run ensemble analysis
        result = self._ensemble_analyze(prompt)

        if result['success']:
            # Store in conversation
            conversation = self.get_conversation(session_id)
            conversation.append({'role': 'user', 'content': prompt})
            conversation.append({'role': 'assistant', 'content': result['analysis']})
            if len(conversation) > 10:
                self.conversations[session_id] = conversation[-10:]

            return {
                'success': True,
                'analysis': result['analysis'],
                'providers_used': result['providers_used'],
                'provider_count': result['provider_count'],
                'logs_analyzed': len(log_entries),
                'conversation_length': len(conversation) // 2,
                'errors': result.get('errors')
            }

        return result

    def ask_followup(self, query: str, session_id: str) -> dict:
        """Ask a follow-up question using ensemble mode."""
        if not self.is_available():
            return {'success': False, 'error': 'No AI providers available.'}

        conversation = self.get_conversation(session_id)
        if not conversation:
            return {'success': False, 'error': 'No previous conversation. Start with analysis first.'}

        # Build context from previous conversation
        context = "Previous conversation:\n"
        for msg in conversation[-4:]:
            role = "User" if msg['role'] == 'user' else "Assistant"
            content = msg['content'][:500] if len(msg['content']) > 500 else msg['content']
            context += f"{role}: {content}\n"

        context += f"\nNew question: {query}"

        # Run ensemble analysis
        result = self._ensemble_analyze(context)

        if result['success']:
            conversation.append({'role': 'user', 'content': query})
            conversation.append({'role': 'assistant', 'content': result['analysis']})
            if len(conversation) > 10:
                self.conversations[session_id] = conversation[-10:]

            return {
                'success': True,
                'analysis': result['analysis'],
                'is_followup': True,
                'providers_used': result['providers_used'],
                'provider_count': result['provider_count'],
                'conversation_length': len(conversation) // 2
            }

        return result

    def get_status(self) -> dict:
        """Get AI agent status."""
        # Refresh Ollama status
        if 'ollama' in self.providers:
            self.providers['ollama']['available'] = self._check_ollama()
        elif self._check_ollama():
            self.providers['ollama'] = {
                'name': 'Ollama (llama3.1:8b)',
                'type': 'ollama',
                'available': True,
                'priority': 5
            }

        # Sort providers by priority
        sorted_providers = sorted(
            [(k, v) for k, v in self.providers.items() if v.get('available', True)],
            key=lambda x: x[1].get('priority', 99)
        )

        available_providers = [p[1]['name'] for p in sorted_providers]
        primary_provider = available_providers[0] if available_providers else None

        return {
            'available': len(available_providers) > 0,
            'provider_count': len(available_providers),
            'provider_names': available_providers,
            'primary_provider': primary_provider,
            'ensemble_available': len(available_providers) > 1,
            'active_conversations': len(self.conversations),
            'claude_available': 'anthropic' in self.providers and self.providers['anthropic'].get('available', False)
        }


_agent_instance = None


def get_ai_agent() -> AIAgent:
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = AIAgent()
    return _agent_instance


def reset_ai_agent():
    global _agent_instance
    _agent_instance = None

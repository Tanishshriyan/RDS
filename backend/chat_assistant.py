"""
RansomGuard AI Chat Assistant
Powered by Perplexity API (Sonar models)
"""
import os
from datetime import datetime
from typing import List, Dict, Optional
from openai import OpenAI

class RansomGuardChatbot:
    def __init__(self, api_key: str, db_path: str = "ransomguard.db"):
        """Initialize Perplexity API chatbot"""
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.perplexity.ai"
        )
        self.db_path = db_path
        self.system_prompt = self._build_system_prompt()
        self.conversation_history = []
    
    def _build_system_prompt(self) -> str:
        """Create specialized system prompt for ransomware detection"""
        return """You are RansomGuard AI Assistant, an expert in ransomware detection and cybersecurity.

Your role:
- Explain ransomware behavioral patterns and detection alerts
- Interpret ML model scores (0.0 = safe, 1.0 = ransomware)
- Guide users through threat remediation
- Answer questions about specific processes and security events
- Provide real-time threat intelligence

Key behavioral features you monitor:
- file_writes, file_deletes, file_renames (file operations)
- cpu_percent, memory_mb (resource usage)
- network_connections (communication patterns)
- entropy_mean (encryption indicators)
- suspicious_extensions (ransomware file types)

Be concise, technical but clear, and always prioritize security. If asked about specific PIDs or events, request context data."""
    
    async def get_system_context(self) -> str:
        """Fetch current system status from database"""
        import aiosqlite
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Get recent threats
                cursor = await db.execute("""
                    SELECT COUNT(*) as threat_count 
                    FROM events 
                    WHERE severity IN ('high', 'critical') 
                    AND timestamp > datetime('now', '-1 hour')
                """)
                row = await cursor.fetchone()
                threat_count = row[0] if row else 0
                
                # Get active processes count
                cursor = await db.execute("SELECT COUNT(*) FROM processes WHERE active = 1")
                row = await cursor.fetchone()
                active_procs = row[0] if row else 0
                
                return f"Current Status: {threat_count} threats (last hour), {active_procs} active processes monitored."
        except Exception as e:
            return f"System context unavailable: {str(e)}"
    
    async def chat(self, user_message: str, include_context: bool = True) -> Dict:
        """Send message to Perplexity API and get response"""
        
        # Build messages array
        messages = [{"role": "system", "content": self.system_prompt}]
        
        # Add system context if requested
        if include_context:
            context = await self.get_system_context()
            messages.append({"role": "system", "content": f"System Context: {context}"})
        
        # Add conversation history (last 10 messages for context)
        messages.extend(self.conversation_history[-10:])
        
        # Add current user message
        messages.append({"role": "user", "content": user_message})
        
        try:
            # Call Perplexity API
            response = self.client.chat.completions.create(
                model="sonar-pro",  # or "sonar" for faster/cheaper responses
                messages=messages,
                temperature=0.2,  # Low temperature for consistent security advice
                max_tokens=500
            )
            
            assistant_message = response.choices[0].message.content
            
            # Update conversation history
            self.conversation_history.append({"role": "user", "content": user_message})
            self.conversation_history.append({"role": "assistant", "content": assistant_message})
            
            return {
                "success": True,
                "response": assistant_message,
                "timestamp": datetime.now().isoformat(),
                "model": "sonar-pro"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def explain_threat(self, pid: int, features: Dict) -> str:
        """Generate explanation for specific threat detection"""
        feature_summary = "\n".join([f"- {k}: {v}" for k, v in features.items()])
        
        prompt = f"""A process (PID {pid}) was flagged as suspicious. Here are its behavioral features:

{feature_summary}

Explain why this might indicate ransomware activity and what actions should be taken."""
        
        result = await self.chat(prompt, include_context=False)
        return result.get("response", "Unable to generate explanation")
    
    def reset_conversation(self):
        """Clear conversation history"""
        self.conversation_history = []

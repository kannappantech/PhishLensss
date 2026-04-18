// PhishLens - Netlify Serverless Function
// Powered by Google Gemini API (Free Tier)
// Your API key is NEVER exposed to the browser.

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };

  // Handle CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  try {
    const { url, depth } = JSON.parse(event.body);

    if (!url) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: "URL is required" }),
      };
    }

    const depthInstructions = {
      quick: "Provide a concise quick-scan analysis with essential findings only.",
      deep: "Provide a thorough deep analysis covering all threat vectors in detail.",
      expert: "Provide an expert-level forensic security report with technical depth, WHOIS insights, TLD risk, and advanced phishing pattern detection.",
    };

    const prompt = `You are PhishLens, an elite cybersecurity AI threat intelligence system. Analyze URLs for phishing, scams, and malicious intent with the precision of a senior security researcher.

${depthInstructions[depth] || depthInstructions.quick}

Analyze this URL for security threats: ${url}

You MUST respond ONLY with a valid JSON object. No markdown, no backticks, no explanations — just raw JSON.

Required JSON structure:
{
  "verdict": "SAFE" or "SUSPICIOUS" or "MALICIOUS",
  "risk_score": number between 0 and 100,
  "summary": "1-2 sentence plain English verdict",
  "url_analysis": {
    "status": "SAFE" or "WARNING" or "DANGER",
    "findings": ["finding1", "finding2", "finding3"]
  },
  "content_analysis": {
    "status": "SAFE" or "WARNING" or "DANGER",
    "findings": ["finding1", "finding2", "finding3"]
  },
  "domain_analysis": {
    "status": "SAFE" or "WARNING" or "DANGER",
    "findings": ["finding1", "finding2", "finding3"]
  },
  "behavioral_analysis": {
    "status": "SAFE" or "WARNING" or "DANGER",
    "findings": ["finding1", "finding2", "finding3"]
  },
  "threat_indicators": {
    "phishing_probability": number between 0 and 100,
    "malware_probability": number between 0 and 100,
    "scam_probability": number between 0 and 100,
    "reputation_score": number between 0 and 100,
    "ssl_trust": number between 0 and 100,
    "domain_age_risk": number between 0 and 100
  },
  "threat_chips": [
    {"label": "SSL Certificate", "value": "Valid or Invalid or Unknown", "type": "safe or warn or danger or info"},
    {"label": "Domain Age", "value": "estimated age", "type": "safe or warn or danger or info"},
    {"label": "TLD Risk", "value": "Low or Medium or High", "type": "safe or warn or danger or info"},
    {"label": "Redirect Risk", "value": "None or Detected", "type": "safe or warn or danger or info"}
  ],
  "recommendations": ["rec1", "rec2", "rec3", "rec4"]
}`;

    // Call Google Gemini API (free tier)
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`;

    const response = await fetch(geminiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 1500,
        },
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error?.message || "Gemini API error");
    }

    // Extract text from Gemini response
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const clean = text.replace(/```json|```/g, "").trim();
    const result = JSON.parse(clean);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(result),
    };

  } catch (err) {
    console.error("PhishLens scan error:", err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: err.message || "Internal server error",
      }),
    };
  }
};

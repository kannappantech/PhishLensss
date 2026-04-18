// PhishLens - Netlify Serverless Function
// This runs on Netlify's servers — your API key is NEVER exposed to the browser.

exports.handler = async (event) => {
  // Only allow POST requests
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  // CORS headers — allows your frontend to call this function
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };

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
      expert:
        "Provide an expert-level forensic security report with technical depth, WHOIS insights, TLD risk, and advanced phishing pattern detection.",
    };

    const systemPrompt = `You are PhishLens, an elite cybersecurity AI threat intelligence system. Analyze URLs for phishing, scams, and malicious intent with the precision of a senior security researcher.

${depthInstructions[depth] || depthInstructions.quick}

You MUST respond ONLY with a valid JSON object. No markdown, no explanations outside the JSON.

JSON Schema:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "risk_score": number (0-100, where 0=completely safe, 100=definitely malicious),
  "summary": "1-2 sentence plain English verdict",
  "url_analysis": {
    "status": "SAFE" | "WARNING" | "DANGER",
    "findings": ["finding1", "finding2", "finding3"]
  },
  "content_analysis": {
    "status": "SAFE" | "WARNING" | "DANGER",
    "findings": ["finding1", "finding2", "finding3"]
  },
  "domain_analysis": {
    "status": "SAFE" | "WARNING" | "DANGER",
    "findings": ["finding1", "finding2", "finding3"]
  },
  "behavioral_analysis": {
    "status": "SAFE" | "WARNING" | "DANGER",
    "findings": ["finding1", "finding2", "finding3"]
  },
  "threat_indicators": {
    "phishing_probability": number (0-100),
    "malware_probability": number (0-100),
    "scam_probability": number (0-100),
    "reputation_score": number (0-100, higher=better reputation),
    "ssl_trust": number (0-100),
    "domain_age_risk": number (0-100, higher=riskier)
  },
  "threat_chips": [
    {"label": "SSL Certificate", "value": "Valid/Invalid/Unknown", "type": "safe|warn|danger|info"},
    {"label": "Domain Age", "value": "Estimated age or New", "type": "safe|warn|danger|info"},
    {"label": "TLD Risk", "value": "Low/Medium/High", "type": "safe|warn|danger|info"},
    {"label": "Redirect Risk", "value": "None/Detected", "type": "safe|warn|danger|info"}
  ],
  "recommendations": ["recommendation1", "recommendation2", "recommendation3", "recommendation4"]
}`;

    // Call Anthropic API using your secret key stored in Netlify environment variables
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY, // Set this in Netlify dashboard
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 1500,
        system: systemPrompt,
        messages: [
          {
            role: "user",
            content: `Analyze this URL for security threats: ${url}`,
          },
        ],
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error?.message || "Anthropic API error");
    }

    const text = data.content?.[0]?.text || "";
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

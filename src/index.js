export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      return new Response(getHTML(), {
        headers: { "Content-Type": "text/html" },
      });
    }

    if (url.pathname === "/analyze" && request.method === "POST") {
      try {
        const body = await request.json();
        const targetUrl = body.url;

        if (!targetUrl) {
          return Response.json({ error: "No URL provided" }, { status: 400 });
        }

        const targetResponse = await fetch(targetUrl, {
          method: "HEAD",
          redirect: "follow",
        });

        const headers = {};
        for (const [key, value] of targetResponse.headers.entries()) {
          headers[key] = value;
        }

        const securityHeaders = {
          "content-security-policy": headers["content-security-policy"] || null,
          "strict-transport-security": headers["strict-transport-security"] || null,
          "x-frame-options": headers["x-frame-options"] || null,
          "x-content-type-options": headers["x-content-type-options"] || null,
          "referrer-policy": headers["referrer-policy"] || null,
          "permissions-policy": headers["permissions-policy"] || null,
          "x-xss-protection": headers["x-xss-protection"] || null,
        };

        const analysis = analyzeHeaders(securityHeaders);

		const aiData = await aiResponse.json();
		console.log("AI RESPONSE:", JSON.stringify(aiData));

        return Response.json({
          url: targetUrl,
          headers: securityHeaders,
          analysis,
        });
      } catch (err) {
        console.log("FULL ERROR:", err);
        console.log("ERROR MESSAGE:", err.message);
        return Response.json({ error: err.message }, { status: 500 });
      }
    }

    return new Response("Not found", { status: 404 });
  },
};

function getHTML() {
  return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'/><meta name='viewport' content='width=device-width, initial-scale=1.0'/><title>Security Analyzer</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;padding:40px 20px}.container{max-width:720px;margin:0 auto}h1{font-size:2rem;font-weight:700;margin-bottom:8px;color:#f97316}p.subtitle{color:#94a3b8;margin-bottom:32px}.input-row{display:flex;gap:12px;margin-bottom:32px}input{flex:1;padding:12px 16px;border-radius:8px;border:1px solid #2d3748;background:#1a1f2e;color:#e2e8f0;font-size:1rem}button{padding:12px 24px;background:#f97316;color:white;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer}button:hover{background:#ea6c0a}button:disabled{background:#4a5568;cursor:not-allowed}.card{background:#1a1f2e;border-radius:12px;padding:24px;margin-bottom:16px;border:1px solid #2d3748}.score{font-size:3rem;font-weight:800}.score.good{color:#48bb78}.score.medium{color:#f6ad55}.score.bad{color:#fc8181}.section-title{font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.1em;color:#94a3b8;margin-bottom:12px}ul{list-style:none}ul li{padding:6px 0;border-bottom:1px solid #2d3748;font-size:0.9rem}ul li:last-child{border-bottom:none}.good-list li::before{content:'checkmark';margin-right:8px;color:#48bb78}.issue-list li::before{content:'x';margin-right:8px;color:#fc8181}.header-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.header-item{background:#0f1117;border-radius:6px;padding:10px;font-size:0.78rem}.header-name{color:#94a3b8;margin-bottom:4px}.header-val{color:#48bb78;word-break:break-all}.header-val.missing{color:#fc8181}.error-msg{color:#fc8181}#loader{display:none;color:#94a3b8;margin-bottom:16px}</style></head><body><div class='container'><h1>Security Analyzer</h1><p class='subtitle'>Analyze any website's security headers and get an AI-powered security report.</p><div class='input-row'><input type='text' id='urlInput' placeholder='https://example.com'/><button id='analyzeBtn'>Analyze</button></div><div id='loader'>Analyzing security headers...</div><div id='results'></div></div><script>function analyze(){var url=document.getElementById('urlInput').value.trim();if(!url)return;var btn=document.getElementById('analyzeBtn');var loader=document.getElementById('loader');var results=document.getElementById('results');btn.disabled=true;loader.style.display='block';results.innerHTML='';fetch('/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:url})}).then(function(r){return r.json()}).then(function(data){if(data.error){results.innerHTML='<div class=\"card\"><p class=\"error-msg\">Error: '+data.error+'</p></div>';return;}var a=data.analysis;var scoreClass=a.score>=70?'good':a.score>=40?'medium':'bad';var headersHtml=Object.entries(data.headers).map(function(e){return'<div class=\"header-item\"><div class=\"header-name\">'+e[0]+'</div><div class=\"header-val'+(e[1]?'':' missing')+'\">'+( e[1]?'Present':'Missing')+'</div></div>'}).join('');results.innerHTML='<div class=\"card\"><div class=\"section-title\">Security Score</div><div class=\"score '+scoreClass+'\">'+a.score+'/100</div><p style=\"margin-top:12px;color:#94a3b8;\">'+a.summary+'</p></div><div class=\"card\"><div class=\"section-title\">What is Good</div><ul class=\"good-list\">'+a.good.map(function(g){return'<li>'+g+'</li>'}).join('')+'</ul></div><div class=\"card\"><div class=\"section-title\">Critical Issues</div><ul class=\"issue-list\">'+a.issues.map(function(i){return'<li>'+i+'</li>'}).join('')+'</ul></div><div class=\"card\"><div class=\"section-title\">Top Recommendation</div><p style=\"font-size:0.9rem;\">'+a.recommendation+'</p></div><div class=\"card\"><div class=\"section-title\">Security Headers</div><div class=\"header-grid\">'+headersHtml+'</div></div>'}).catch(function(e){results.innerHTML='<div class=\"card\"><p class=\"error-msg\">Error: '+e.message+'</p></div>'}).finally(function(){btn.disabled=false;loader.style.display='none'});}document.getElementById('analyzeBtn').addEventListener('click',analyze);document.getElementById('urlInput').addEventListener('keydown',function(e){if(e.key==='Enter')analyze();});</script></body></html>";
}

function analyzeHeaders(headers) {
  let score = 100;
  const good = [];
  const issues = [];

  if (headers["content-security-policy"]) {
    good.push("Content Security Policy is configured");
  } else {
    issues.push("Missing Content Security Policy (CSP)");
    score -= 25;
  }

  if (headers["strict-transport-security"]) {
    good.push("HSTS is enabled");
  } else {
    issues.push("Strict-Transport-Security header missing");
    score -= 20;
  }

  if (headers["x-frame-options"]) {
    good.push("Clickjacking protection enabled (X-Frame-Options)");
  } else {
    issues.push("Missing X-Frame-Options header");
    score -= 15;
  }

  if (headers["x-content-type-options"]) {
    good.push("MIME sniffing protection enabled");
  } else {
    issues.push("Missing X-Content-Type-Options header");
    score -= 10;
  }

  if (headers["referrer-policy"]) {
    good.push("Referrer Policy configured");
  } else {
    issues.push("Referrer-Policy not configured");
    score -= 10;
  }

  score = Math.max(score, 0);

  return {
    score,
    summary: score > 70
      ? "The website implements several important HTTP security headers."
      : "The website is missing important HTTP security headers that protect against common web attacks.",
    good: good.slice(0,3),
    issues: issues.slice(0,3),
    recommendation: issues.length
      ? "Implement missing security headers such as Content-Security-Policy and HSTS to significantly improve web security."
      : "Security headers appear well configured."
  };
}

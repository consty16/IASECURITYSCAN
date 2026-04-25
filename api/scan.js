export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Método no permitido" });
  }

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL requerida" });

  let resultados = [];
  let score = 0;
  let domain = new URL(url).hostname.toLowerCase();

  try {

    // 🟢 GOOGLE SAFE BROWSING
    try {
      const safeRes = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client: { clientId: "scanner", clientVersion: "1.0" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url }]
            }
          })
        }
      );

      const safeData = await safeRes.json();
      if (safeData.matches) {
        resultados.push("🚨 Phishing/Malware detectado (Google)");
        score += 70;
      }
    } catch {}

    // 🟡 VIRUSTOTAL
    try {
      await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": process.env.VT_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({ url })
      });

      resultados.push("Analizado por VirusTotal");
      score += 20;
    } catch {}

    // 🟡 WHOIS
    try {
      const whoisRes = await fetch(
        `https://api.api-ninjas.com/v1/whois?domain=${domain}`,
        { headers: { "X-Api-Key": process.env.WHOIS_KEY } }
      );

      const whois = await whoisRes.json();

      if (whois.creation_date) {
        const created = new Date(whois.creation_date);
        const ageDays = (Date.now() - created) / (1000 * 60 * 60 * 24);

        if (ageDays < 30) {
          resultados.push("Dominio muy nuevo (alto riesgo)");
          score += 25;
        }
      }
    } catch {}

    // 🟣 OTX
    try {
      const otxRes = await fetch(
        `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`,
        { headers: { "X-OTX-API-KEY": process.env.OTX_KEY } }
      );

      const otxData = await otxRes.json();

      if (otxData.pulse_info?.count > 0) {
        resultados.push("Reportado en inteligencia de amenazas (OTX)");
        score += 30;
      }
    } catch {}

    // 🔵 IP
    let ip = null;
    try {
      ip = await fetch(`https://dns.google/resolve?name=${domain}`)
        .then(r => r.json())
        .then(d => d.Answer ? d.Answer[0].data : null);
    } catch {}

    if (ip) {

      // 🔵 ABUSE
      try {
        const abuseRes = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
          {
            headers: {
              Key: process.env.ABUSE_KEY,
              Accept: "application/json"
            }
          }
        );

        const abuseData = await abuseRes.json();

        if (abuseData.data?.abuseConfidenceScore > 50) {
          resultados.push("IP maliciosa reportada");
          score += 25;
        }
      } catch {}

      // 🟦 SHODAN
      try {
        const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
        const shodanData = await shodanRes.json();

        if (shodanData.ports?.length > 0) {
          resultados.push(`Puertos abiertos: ${shodanData.ports.join(", ")}`);
          score += 5;
        }
      } catch {}

      // 🌐 GEO
      try {
        const geoRes = await fetch(`http://ip-api.com/json/${ip}`);
        const geoData = await geoRes.json();

        if (geoData.country) {
          resultados.push(`Servidor en: ${geoData.country}`);
        }
      } catch {}
    }

    // 🌐 DNS
    try {
      const dnsRes = await fetch(`https://dns.google/resolve?name=${domain}&type=NS`);
      const dnsData = await dnsRes.json();

      if (!dnsData.Answer) {
        resultados.push("DNS sospechoso");
        score += 15;
      }
    } catch {}

    // 🧠 HTML + CLONES
    try {
      const htmlRes = await fetch(url);
      const html = await htmlRes.text();
      const htmlLower = html.toLowerCase();

      // login forms
      if (html.includes("<form") && html.match(/password/i)) {
        resultados.push("Formulario de login detectado");
        score += 25;
      }

      // contenido sensible
      if (html.match(/paypal|bank|login|verify/i)) {
        resultados.push("Contenido sensible detectado");
        score += 15;
      }

      // robo credenciales
      if (
        html.match(/usuario|dni|clave|password|token/i) &&
        html.match(/banco|bank|login|cuenta/i)
      ) {
        resultados.push("🚨 Robo de credenciales");
        score += 40;
      }

      // 💣 LISTA COMPLETA
      const marcas = [
        "banco de la nacion","nacion","bna",
        "banco provincia","provincia","bapro",
        "banco ciudad","ciudad",
        "bancor","cordoba","pampa","corrientes","neuquen",
        "santiago","chubut","santacruz","tucuman",

        "banco galicia","galicia","santander","bbva","macro",
        "patagonia","hsbc","icbc","supervielle","hipotecario",
        "credicoop","comafi","cmf","columbia","valores","bst",
        "banco del sol","delsol","brubank","openbank",

        "mercado pago","mercadopago","uala","personal pay","personalpay",
        "naranja x","naranjax","lemon","lemon cash","lemoncash",
        "prex","claro pay","claropay","belo","astropay","fiwind",
        "cocos","cocos pay","cocospay","n1u",

        "modo","cuenta dni","cuentadni","bna+","bnamas",
        "reba","go galicia","go bbva","go santander",

        "google pay","googlepay","apple pay","applepay",
        "paypal","payoneer",

        "plus pagos","pluspagos","taca taca","tacataca",
        "moni","pago24"
      ];

      for (let marca of marcas) {
        if (htmlLower.includes(marca) && !domain.includes(marca)) {
          resultados.push(`🚨 Clon de ${marca}`);
          score += 50;
        }
      }

    } catch {}

    // 💣 HEURÍSTICAS
    if (!url.startsWith("https")) {
      resultados.push("Sin HTTPS");
      score += 15;
    }

    if (/login|verify|secure|update/i.test(url)) {
      resultados.push("Patrón phishing");
      score += 25;
    }

    if (url.includes("@") || url.includes("-")) {
      resultados.push("Dominio sospechoso");
      score += 10;
    }

    if (url.match(/\.(apk|exe|zip|rar)$/i)) {
      resultados.push("Archivo peligroso");
      score += 30;
    }

    // 🎯 RESULTADO
    let riesgo = "BAJO";
    if (score > 80) riesgo = "CRITICO";
    else if (score > 50) riesgo = "ALTO";
    else if (score > 20) riesgo = "MEDIO";

    res.json({ url, riesgo, score, resultados });

  } catch {
    res.status(500).json({ error: "Error en el análisis" });
  }
}
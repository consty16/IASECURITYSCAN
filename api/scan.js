import { createRequire } from "module";
const require = createRequire(import.meta.url);
const entidades = require("../entidades.json");

// 🔥 FETCH CON TIMEOUT
const fetchSafe = async (url, options = {}, timeout = 4000) => {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Timeout")), timeout)
    )
  ]);
};

// 🚪 Puertos que SÍ son sospechosos (80 y 443 son NORMALES)
const PUERTOS_SOSPECHOSOS = [22, 23, 3389, 4444, 5900, 8080, 8443, 9200, 27017];

// ✅ FIX WHOIS: normaliza cualquier formato de fecha
const parsearFechaWhois = (raw) => {
  if (!raw) return null;
  const valor = Array.isArray(raw) ? raw[0] : raw;
  if (typeof valor === "number") return new Date(valor * 1000);
  const d = new Date(valor);
  return isNaN(d.getTime()) ? null : d;
};

// 🔐 Dominios autorizados para CORS
const DOMINIOS_PERMITIDOS = [
  "https://iasecurityscan.vercel.app",
  "http://localhost:3000",       // para desarrollo local
  "http://localhost:5173"        // para Vite local
];

export default async function handler(req, res) {

  // 🔐 CORS — solo dominios autorizados
  const origin = req.headers.origin;
  if (DOMINIOS_PERMITIDOS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-api-key");

  // Preflight request del navegador — responder OK
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Método no permitido" });
  }
  // ─── TODO LO DE ABAJO ES EXACTAMENTE IGUAL, SIN CAMBIOS ───

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL requerida" });
  if (!url.startsWith("http")) {
    return res.status(400).json({ error: "URL inválida" });
  }

  let resultados = [];
  let score = 0;
  let domain;

  try {
    domain = new URL(url).hostname.toLowerCase();
  } catch {
    return res.status(400).json({ error: "URL inválida" });
  }

  // ✅ Verificar entidad oficial
  const entidad = Array.isArray(entidades)
    ? entidades.find(
        e => domain === e.dominio || domain.endsWith("." + e.dominio)
      )
    : null;

  const pareceFinanciero = /banco|pago|pay|wallet|tarjeta|credito|fintech|uala|mercado/i.test(domain);

  if (entidad) {
    resultados.push(`✅ Sitio oficial verificado: ${entidad.nombre}`);
    score -= 10;
  } else if (pareceFinanciero) {
    resultados.push("🚨 Parece un sitio financiero pero NO está en la lista oficial");
    score += 30;
  }

  try {
    // 🟢 GOOGLE SAFE BROWSING
    try {
      const safeRes = await fetchSafe(
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
      const safeData = await safeRes.json().catch(() => ({}));
      if (safeData.matches && safeData.matches.length > 0) {
        resultados.push("🚨 Phishing/Malware detectado por Google Safe Browsing");
        score += 40;
      } else {
        resultados.push("✅ Sin amenazas en Google Safe Browsing");
      }
    } catch {
      resultados.push("⚠️ Google Safe Browsing no disponible");
    }

    // 🟡 VIRUSTOTAL — envío + lectura real
    try {
      const vtSubmit = await fetchSafe(
        "https://www.virustotal.com/api/v3/urls",
        {
          method: "POST",
          headers: {
            "x-apikey": process.env.VT_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({ url })
        }
      );
      const vtSubmitData = await vtSubmit.json().catch(() => ({}));
      const analysisId = vtSubmitData?.data?.id;

      if (analysisId) {
        await new Promise(r => setTimeout(r, 2000));
        const vtResult = await fetchSafe(
          `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
          { headers: { "x-apikey": process.env.VT_API_KEY } },
          6000
        );
        const vtData = await vtResult.json().catch(() => ({}));
        const stats = vtData?.data?.attributes?.stats;

        if (stats) {
          const malicious = stats.malicious || 0;
          const suspicious = stats.suspicious || 0;
          if (malicious > 0 || suspicious > 0) {
            resultados.push(`🚨 VirusTotal: ${malicious} motor(es) lo marcan como malicioso`);
            score += malicious > 3 ? 40 : 20;
          } else {
            resultados.push("✅ VirusTotal: sin detecciones maliciosas");
          }
        } else {
          resultados.push("⏳ VirusTotal: análisis en proceso");
        }
      } else {
        resultados.push("⚠️ VirusTotal: no se pudo enviar la URL");
      }
    } catch {
      resultados.push("⚠️ VirusTotal no disponible");
    }

    // 🟡 WHOIS — FIX NaN
    try {
      const whoisRes = await fetchSafe(
        `https://api.api-ninjas.com/v1/whois?domain=${domain}`,
        { headers: { "X-Api-Key": process.env.WHOIS_KEY } }
      );
      const whois = await whoisRes.json().catch(() => ({}));
      const created = parsearFechaWhois(whois.creation_date);

      if (created) {
        const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
        if (ageDays < 30) {
          resultados.push(`🚨 Dominio muy nuevo: ${Math.floor(ageDays)} días de antigüedad`);
          score += 25;
        } else if (ageDays < 90) {
          resultados.push(`⚠️ Dominio reciente: ${Math.floor(ageDays)} días de antigüedad`);
          score += 10;
        } else {
          const años = Math.floor(ageDays / 365);
          const meses = Math.floor((ageDays % 365) / 30);
          resultados.push(`✅ Dominio con ${años} año(s) y ${meses} mes(es) de antigüedad`);
        }
      } else {
        resultados.push("⚠️ WHOIS: no se encontró fecha de creación");
      }
    } catch {
      resultados.push("⚠️ WHOIS no disponible");
    }

    // 🟣 OTX AlienVault
    try {
      const otxRes = await fetchSafe(
        `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`,
        { headers: { "X-OTX-API-KEY": process.env.OTX_KEY } }
      );
      const otxData = await otxRes.json().catch(() => ({}));
      if (otxData.pulse_info?.count > 0) {
        resultados.push(`🚨 Reportado en ${otxData.pulse_info.count} alerta(s) de inteligencia (OTX)`);
        score += 30;
      } else {
        resultados.push("✅ Sin reportes en OTX AlienVault");
      }
    } catch {
      resultados.push("⚠️ OTX no disponible");
    }

    // 🔵 Resolución de IP
    let ip = null;
    try {
      const dnsIpRes = await fetchSafe(
        `https://dns.google/resolve?name=${domain}&type=A`,
        {},
        5000
      );
      const dnsIpData = await dnsIpRes.json().catch(() => ({}));
      ip = dnsIpData?.Answer?.find(r => r.type === 1)?.data || null;
      if (ip) {
        resultados.push(`🌐 IP resuelta: ${ip}`);
      } else {
        resultados.push("⚠️ No se pudo resolver la IP del dominio");
        score += 10;
      }
    } catch {
      resultados.push("⚠️ Resolución DNS fallida");
    }

    // 🔵 ABUSEIPDB
    if (ip) {
      try {
        const abuseRes = await fetchSafe(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
          {
            headers: {
              "Key": process.env.ABUSE_KEY,
              "Accept": "application/json"
            }
          }
        );
        const abuseData = await abuseRes.json().catch(() => ({}));
        const abuseScore = abuseData.data?.abuseConfidenceScore;
        if (abuseScore !== undefined) {
          if (abuseScore > 50) {
            resultados.push(`🚨 IP con ${abuseScore}% de índice de abuso (AbuseIPDB)`);
            score += 25;
          } else if (abuseScore > 10) {
            resultados.push(`⚠️ IP con actividad sospechosa leve: ${abuseScore}%`);
            score += 10;
          } else {
            resultados.push("✅ IP sin reportes de abuso");
          }
        }
      } catch {
        resultados.push("⚠️ AbuseIPDB no disponible");
      }
    }

    // 🟦 SHODAN InternetDB
    if (ip) {
      try {
        const shodanRes = await fetchSafe(`https://internetdb.shodan.io/${ip}`);
        const shodanData = await shodanRes.json().catch(() => ({}));

        if (shodanData.ports?.length > 0) {
          const puertosRiesgosos = shodanData.ports.filter(p =>
            PUERTOS_SOSPECHOSOS.includes(p)
          );
          if (puertosRiesgosos.length > 0) {
            resultados.push(`⚠️ Puertos de riesgo detectados: ${puertosRiesgosos.join(", ")}`);
            score += 15;
          } else {
            resultados.push(`✅ Puertos abiertos normales (${shodanData.ports.join(", ")})`);
          }
        } else {
          resultados.push("✅ Sin puertos sospechosos (Shodan)");
        }

        if (shodanData.vulns?.length > 0) {
          resultados.push(`🚨 Vulnerabilidades conocidas: ${shodanData.vulns.join(", ")}`);
          score += 20;
        }
      } catch {
        resultados.push("⚠️ Shodan no disponible");
      }
    }

    // 🔴 URLSCAN — envío + polling resultado real
    try {
      const urlscanSubmit = await fetchSafe(
        "https://urlscan.io/api/v1/scan/",
        {
          method: "POST",
          headers: {
            "API-Key": process.env.URLSCAN_KEY,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url, visibility: "public" })
        }
      );
      const urlscanSubmitData = await urlscanSubmit.json().catch(() => ({}));
      const scanUuid = urlscanSubmitData?.uuid;

      if (scanUuid) {
        await new Promise(r => setTimeout(r, 5000));
        const urlscanResult = await fetchSafe(
          `https://urlscan.io/api/v1/result/${scanUuid}/`,
          {},
          8000
        );
        const urlscanData = await urlscanResult.json().catch(() => ({}));
        const veredicto = urlscanData?.verdicts?.overall;
        const malicioso = veredicto?.malicious;
        const puntaje = veredicto?.score || 0;
        const marcasDetectadas = urlscanData?.verdicts?.urlscan?.brands || [];

        if (malicioso) {
          resultados.push(`🚨 URLScan: sitio marcado como MALICIOSO (score: ${puntaje})`);
          score += 35;
        } else if (puntaje > 50) {
          resultados.push(`⚠️ URLScan: comportamiento sospechoso (score: ${puntaje})`);
          score += 20;
        } else {
          resultados.push("✅ URLScan: sin comportamiento malicioso detectado");
        }

        if (marcasDetectadas.length > 0 && !entidad) {
          const nombres = marcasDetectadas.map(b => b.name || b).join(", ");
          resultados.push(`🚨 URLScan detectó imitación de marca: ${nombres}`);
          score += 30;
        }
      } else {
        resultados.push("⚠️ URLScan: no se pudo iniciar el análisis");
      }
    } catch {
      resultados.push("⚠️ URLScan no disponible");
    }

    // 🌍 GEO IP
    if (ip) {
      try {
        const geoRes = await fetchSafe(`https://ip-api.com/json/${ip}`);
        const geoData = await geoRes.json().catch(() => ({}));
        if (geoData.country) {
          resultados.push(`🌍 Servidor en: ${geoData.country} — ${geoData.city || "ciudad desconocida"}`);
          const paisesRiesgo = ["Russia", "China", "North Korea", "Iran"];
          if (paisesRiesgo.includes(geoData.country)) {
            resultados.push("⚠️ País asociado a alto riesgo cibernético");
            score += 15;
          }
        }
      } catch {
        resultados.push("⚠️ Geolocalización no disponible");
      }
    }

    // 🌐 DNS NS Records
    try {
      const dnsRes = await fetchSafe(
        `https://dns.google/resolve?name=${domain}&type=NS`,
        {},
        6000
      );
      const dnsData = await dnsRes.json().catch(() => ({}));
      if (!dnsData.Answer || dnsData.Answer.length === 0) {
        resultados.push("⚠️ Sin registros NS encontrados");
      } else {
        resultados.push("✅ Registros DNS NS válidos");
      }
    } catch {
      resultados.push("⚠️ Verificación DNS NS no disponible (timeout)");
    }

    // 🧠 ANÁLISIS HTML
    let html = "";
    try {
      const htmlRes = await fetchSafe(url, {}, 5000);
      html = await htmlRes.text();
    } catch {
      resultados.push("⚠️ No se pudo analizar el HTML del sitio");
    }

    if (html) {
      const htmlLower = html.toLowerCase();

      if (html.includes("<form") && /password|contraseña/i.test(html)) {
        resultados.push("⚠️ Formulario de login detectado en el HTML");
        score += 25;
      }

      if (/usuario|dni|clave|password|token/i.test(html)) {
        resultados.push("🚨 Posible captura de credenciales en el HTML");
        score += 40;
      }

      const marcas = ["mercado pago", "uala", "paypal", "bbva", "santander", "banco galicia"];
      for (const marca of marcas) {
        if (htmlLower.includes(marca) && !entidad) {
          resultados.push(`🚨 Menciona "${marca}" sin ser sitio oficial verificado`);
          score += 50;
        }
      }

      if (/window\.location|document\.location|meta.*refresh/i.test(html)) {
        if (score > 20) {
          resultados.push("⚠️ Redirección automática detectada (combinada con otras señales)");
          score += 10;
        } else {
          resultados.push("ℹ️ Redirección automática detectada (normal en sitios legítimos)");
        }
      }
    }

    // 💣 HEURÍSTICAS DE URL
    if (!url.startsWith("https")) {
      resultados.push("⚠️ Sitio sin HTTPS — conexión no cifrada");
      score += 10;
    }

    if (/login|verify|secure|update|account|confirm/i.test(url)) {
      resultados.push("⚠️ URL con palabras clave típicas de phishing");
      score += 15;
    }

    if (url.includes("@")) {
      resultados.push("🚨 URL contiene '@' — técnica de engaño clásica");
      score += 20;
    }

    const guiones = (domain.match(/-/g) || []).length;
    if (guiones > 3) {
      resultados.push(`⚠️ Dominio con ${guiones} guiones — patrón sospechoso`);
      score += 10;
    }

    if (url.match(/\.(apk|exe|zip|rar)$/i)) {
      resultados.push("🚨 URL apunta a una descarga potencialmente peligrosa");
      score += 30;
    }

    const subdominios = domain.split(".").length - 2;
    if (subdominios > 2) {
      resultados.push(`⚠️ Exceso de subdominios (${subdominios}) — técnica de camuflaje`);
      score += 15;
    }

    // 🎯 NIVEL DE RIESGO FINAL
    score = Math.max(0, score);
    let riesgo = "BAJO";
    if (score > 80) riesgo = "CRITICO";
    else if (score > 50) riesgo = "ALTO";
    else if (score > 20) riesgo = "MEDIO";

    return res.json({ url, riesgo, score, resultados });

  } catch (error) {
    console.error("ERROR REAL:", error?.message, error?.stack);
    return res.status(500).json({ error: error?.message || "Error en el análisis" });
  }
}

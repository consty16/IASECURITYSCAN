export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { url } = req.body;

  return res.status(200).json({
    riesgo: "Bajo",
    score: 10,
    resultados: ["Test funcionando"]
  });
}

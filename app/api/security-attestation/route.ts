// Temporary authenticated incident verification; removed after rollout evidence is saved.
import tls from "node:tls";
import https from "node:https";
import { createHash, X509Certificate } from "node:crypto";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const blocked = new Set(["7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D", "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5", "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4", "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"]);
const hosts = ["ov-g3c-aaa-emudhra.we-have-a-problem.com", "ev-g3c-emudhra.we-have-a-problem.com", "ov-g3b-aaa-emudhra.we-have-a-problem.com", "ov-g3b-emudhra.we-have-a-problem.com", "ev-g3b-aaa-emudhra.we-have-a-problem.com", "ev-g3c-aaa-emudhra.we-have-a-problem.com", "ev-g3b-emudhra.we-have-a-problem.com", "dv-g3b-noct-emudhra.we-have-a-problem.com", "ov-g3c-emudhra.we-have-a-problem.com", "dv-g3b-aaa-emudhra.we-have-a-problem.com", "dv-g3c-aaa-emudhra.we-have-a-problem.com", "dv-g3b-aaa-noct-emudhra.we-have-a-problem.com", "dv-g3b-emudhra.we-have-a-problem.com", "dv-g3c-emudhra.we-have-a-problem.com"];
function probe(host: string): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const req = https.get("https://" + host, { timeout: 6000 }, (res) => {
      res.resume(); resolve({ host, status: "ACCEPTED_CHAIN", http: res.statusCode });
    });
    req.on("error", (error: NodeJS.ErrnoException) => resolve({ host, status: "REJECTED", code: error.code }));
    req.on("timeout", () => req.destroy(new Error("timeout")));
  });
}
export async function GET(request: Request) {
  const key = request.headers.get("x-security-audit-key") || "";
  if (createHash("sha256").update(key).digest("hex") !== "67e376f8c7b0ad8bfe61a9cffbc587612601ac4606ce42fa57de095c972af6f1") return new Response(null, { status: 404 });
  const certificates = (tls as typeof tls & { getCACertificates(type: "default"): string[] }).getCACertificates("default");
  const blockedRoots = certificates.map((pem) => new X509Certificate(pem).fingerprint256.replaceAll(":", "")).filter((fp) => blocked.has(fp));
  const probes = await Promise.all([...hosts, "example.com"].map(probe));
  let fetchProbe: Record<string, unknown>;
  try {
    const response = await fetch("https://dv-g3b-emudhra.we-have-a-problem.com", { signal: AbortSignal.timeout(6000) });
    await response.body?.cancel(); fetchProbe = { status: "ACCEPTED_CHAIN", http: response.status };
  } catch (error) {
    const cause = error as { cause?: { code?: string }; code?: string };
    fetchProbe = { status: "REJECTED", code: cause.cause?.code || cause.code };
  }
  return Response.json({ node: process.version, certificates: certificates.length, blockedRoots, probes, fetchProbe }, { headers: { "Cache-Control": "private, no-store" } });
}

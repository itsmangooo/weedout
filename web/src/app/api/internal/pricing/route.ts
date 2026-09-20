import { publicResponse } from "@/server/http/responses";
const features = [
  "Unlimited projects", "Full dependency tree analysis", "Automated Node reachability with evidence",
  "Custom scan rules and .weedout.yml", "Email, Discord and custom webhook alerts",
  "One year of alert history", "CLI and CI-compatible exit behavior",
];
export async function GET() { return publicResponse({ data: { plans: [{ id: "free", name: "Free", price: "$0", features }] } }, 300); }

import type { NetworkEvent } from "../../core/types.js";

const PRIVATE_IP_PATTERNS = [
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^127\./,
  /^::1$/,
  /^fe80:/i,
  /^0\.0\.0\.0$/
];

const REGISTRY_CDN_RANGES = [
  /^104\.16\./,
  /^104\.17\./,
  /^104\.18\./,
  /^104\.19\./,
  /^104\.2[0-9]\./,
  /^104\.3[0-1]\./,
  /^151\.101\./,
  /^146\.75\./,
  /^140\.82\./,
  /^185\.199\./,
  /^192\.30\.25[2-5]\./,
  /^13\.107\./,
  /^20\.20[1-7]\./,
  /^52\.84\./,
  /^54\.230\./,
  /^54\.239\./,
  /^99\.84\./
];

const NOISE_PORTS = new Set([53, 0]);

const NOISE_SYSCALLS = new Set(["sendto", "recvfrom", "recvmsg", "sendmsg"]);

export interface NetworkClassification {
  total: number;
  suspicious: NetworkEvent[];
  benign: NetworkEvent[];
  uniqueSuspiciousDestinations: number;
  destinationsPreview: string;
}

export function classifyNetworkActivity(events: NetworkEvent[]): NetworkClassification {
  const suspicious: NetworkEvent[] = [];
  const benign: NetworkEvent[] = [];

  for (const event of events) {
    if (isBenign(event)) {
      benign.push(event);
    } else {
      suspicious.push(event);
    }
  }

  const counts = new Map<string, number>();
  for (const event of suspicious) {
    const key = `${event.address}:${event.port}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const ranked = Array.from(counts.entries()).sort((left, right) => right[1] - left[1]);
  const preview = ranked
    .slice(0, 3)
    .map(([destination, count]) => (count > 1 ? `${destination} (×${count})` : destination))
    .join(", ");
  const suffix = ranked.length > 3 ? `, +${ranked.length - 3} more` : "";

  return {
    total: events.length,
    suspicious,
    benign,
    uniqueSuspiciousDestinations: ranked.length,
    destinationsPreview: ranked.length ? `${preview}${suffix}` : ""
  };
}

function isBenign(event: NetworkEvent): boolean {
  if (NOISE_PORTS.has(event.port)) return true;
  if (NOISE_SYSCALLS.has(event.syscall)) return true;
  if (PRIVATE_IP_PATTERNS.some((pattern) => pattern.test(event.address))) return true;
  if (REGISTRY_CDN_RANGES.some((pattern) => pattern.test(event.address))) return true;
  return false;
}

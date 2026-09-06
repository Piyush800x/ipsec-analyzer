/** The full parameter table, AttributeCell throughout. Step 7.8. */

import { notFound } from "next/navigation";

import { AttributeCell } from "@/components/AttributeCell";
import { Card } from "@/components/ui";
import { getAssessment } from "@/lib/api";
import type { SecurityAssociation } from "@/lib/types";

const ROWS: { field: keyof SecurityAssociation; label: string }[] = [
  { field: "ike_version", label: "IKE version" },
  { field: "ike_exchange_mode", label: "Exchange mode" },
  { field: "encryption_alg", label: "Encryption algorithm" },
  { field: "encryption_keylen", label: "Key length (bits)" },
  { field: "integrity_alg", label: "Integrity algorithm" },
  { field: "prf_alg", label: "PRF" },
  { field: "dh_group", label: "Diffie-Hellman group" },
  { field: "operating_mode", label: "Operating mode" },
  { field: "pfs_enabled", label: "Perfect Forward Secrecy" },
  { field: "auth_method", label: "Authentication method" },
  { field: "negotiated_lifetime_s", label: "Negotiated lifetime (s)" },
  { field: "observed_rekey_s", label: "Observed rekey interval (s)" },
  { field: "esn_negotiated", label: "Extended Sequence Numbers" },
  { field: "replay_sane", label: "Sequence numbers sane" },
  { field: "nat_traversal", label: "NAT traversal" },
  { field: "downgrade_available", label: "Weaker proposal offered" },
];

export default async function ConfigurationPage({ params }: PageProps<"/assessments/[id]">) {
  const { id } = await params;
  let assessment;
  try {
    assessment = await getAssessment(id);
  } catch {
    notFound();
  }

  return (
    <div className="flex flex-col gap-6">
      {assessment.security_associations.map((sa) => (
        <Card key={sa.spi_initiator} title={`SA ${sa.spi_initiator} · ${sa.src} → ${sa.dst}`}>
          <dl className="divide-y divide-zinc-100 dark:divide-zinc-800">
            {ROWS.map(({ field, label }) => (
              <div
                key={String(field)}
                className="grid grid-cols-1 gap-1 py-3 sm:grid-cols-[14rem_1fr] sm:gap-4"
              >
                <dt className="text-sm text-zinc-600 dark:text-zinc-400">{label}</dt>
                <dd>
                  <AttributeCell attr={sa[field] as never} />
                </dd>
              </div>
            ))}
          </dl>
        </Card>
      ))}
    </div>
  );
}

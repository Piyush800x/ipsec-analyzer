/** Inferred inner traffic. Step 7.10. */

import { notFound } from "next/navigation";

import { TrafficTimeline } from "@/components/TrafficTimeline";
import { Card } from "@/components/ui";
import { getAssessment } from "@/lib/api";

export default async function TrafficPage({ params }: PageProps<"/assessments/[id]">) {
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
          <TrafficTimeline predictions={sa.inner_traffic} />
        </Card>
      ))}
    </div>
  );
}

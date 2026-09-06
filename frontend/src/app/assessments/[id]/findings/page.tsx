/** Findings view. Step 7.9. */

import { notFound } from "next/navigation";

import { FindingsTable } from "@/components/FindingsTable";
import { EmptyState } from "@/components/ui";
import { getAssessment } from "@/lib/api";

export default async function FindingsPage({
  params,
  searchParams,
}: PageProps<"/assessments/[id]/findings">) {
  const { id } = await params;
  const { technique } = await searchParams;

  let assessment;
  try {
    assessment = await getAssessment(id);
  } catch {
    notFound();
  }

  if (assessment.findings.length === 0) {
    return (
      <EmptyState
        title="No findings"
        detail="Nothing in the policy matched this deployment. That is a result, not an error."
      />
    );
  }

  return (
    <FindingsTable
      findings={assessment.findings}
      initialTechnique={typeof technique === "string" ? technique : undefined}
    />
  );
}

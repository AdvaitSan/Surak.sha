import ReportClient from "./reportClient";

export async function generateStaticParams() {
  return [];
}

export default function ReportDetailPage({ params }: { params: { id: string } }) {
  return <ReportClient id={params.id} />;
} 
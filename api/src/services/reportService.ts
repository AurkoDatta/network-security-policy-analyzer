import PDFDocument from 'pdfkit';
import { AnalysisDocument } from '../models/Analysis';
import { PolicyDocument } from '../models/Policy';

export function generateReportPdf(policy: PolicyDocument, analysis: AnalysisDocument): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    const chunks: Buffer[] = [];

    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    doc.fontSize(20).text(`Policy Analysis Report: ${policy.name}`, { underline: true });
    doc.moveDown();
    doc.fontSize(12).text(`Source type: ${policy.source_type}`);
    doc.text(`Generated: ${analysis.generated_at.toISOString()}`);
    doc.moveDown();

    doc.fontSize(16).text('Risk Score');
    doc.fontSize(12).text(`Overall: ${analysis.risk_score.overall}`);
    doc.text(`Permissiveness: ${analysis.risk_score.permissiveness}`);
    doc.text(`Exposure: ${analysis.risk_score.exposure}`);
    doc.text(`Compliance violations: ${analysis.risk_score.compliance_violations}`);
    doc.text(`Unused: ${analysis.risk_score.unused}`);
    doc.moveDown();

    doc.fontSize(16).text('Findings');
    if (analysis.findings.length === 0) {
      doc.fontSize(12).text('No findings.');
    }
    for (const finding of analysis.findings) {
      doc.moveDown(0.5);
      doc.fontSize(13).text(`[${finding.severity.toUpperCase()}] ${finding.type} — rule ${finding.rule_id}`);
      doc.fontSize(11).text(finding.description);
      doc.fontSize(11).text(`Recommendation: ${finding.recommendation}`);
    }

    doc.end();
  });
}

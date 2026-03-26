import { type ActionFunctionArgs } from '@remix-run/cloudflare';
import { generateOsvPdf } from '~/lib/pdf-generator';

export async function action({ request }: ActionFunctionArgs) {
  try {
    const body = (await request.json()) as any;
    const { vulnerabilities, stats, scannedPackages, scannedFiles, scanDuration } = body;

    if (!vulnerabilities || !stats) {
      return new Response('Missing required data', { status: 400 });
    }

    console.log('[OSV PDF] Generating PDF report...');
    console.log('[OSV PDF] Vulnerabilities:', vulnerabilities.length);
    console.log('[OSV PDF] Stats:', stats);
    console.log('[OSV PDF] Packages scanned:', scannedPackages);
    console.log('[OSV PDF] Files scanned:', scannedFiles);

    const pdfBuffer = await generateOsvPdf(
      vulnerabilities,
      stats,
      scannedPackages || 0,
      scannedFiles || 0,
      scanDuration || 0,
    );

    console.log('[OSV PDF] PDF generated successfully');
    console.log('[OSV PDF] Size:', pdfBuffer.length, 'bytes');

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    const filename = `osv-report-${timestamp}.pdf`;

    return new Response(pdfBuffer, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Length': pdfBuffer.length.toString(),
      },
    });
  } catch (error: any) {
    console.error('[OSV PDF] Error generating PDF:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

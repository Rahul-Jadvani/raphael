import type { AppLoadContext, EntryContext } from '@remix-run/node';
import { RemixServer } from '@remix-run/react';
import { isbot } from 'isbot';
import { renderToPipeableStream } from 'react-dom/server';
import { renderHeadToString } from 'remix-island';
import { Head } from './root';
import { themeStore } from '~/lib/stores/theme';
import { PassThrough } from 'node:stream';

const ABORT_DELAY = 5_000;

export default function handleRequest(
  request: Request,
  responseStatusCode: number,
  responseHeaders: Headers,
  remixContext: EntryContext,
  _loadContext: AppLoadContext,
) {
  return new Promise<Response>((resolve, reject) => {
    let shellRendered = false;
    const userAgent = request.headers.get('user-agent') || '';
    const bot = isbot(userAgent);

    const passthrough = new PassThrough();

    const head = renderHeadToString({ request, remixContext, Head });
    const htmlStart = `<!DOCTYPE html><html lang="en" data-theme="${themeStore.value}"><head>${head}</head><body><div id="root" class="w-full h-full">`;
    const htmlEnd = '</div></body></html>';

    const { pipe, abort } = renderToPipeableStream(<RemixServer context={remixContext} url={request.url} />, {
      [bot ? 'onAllReady' : 'onShellReady']() {
        shellRendered = true;

        responseHeaders.set('Content-Type', 'text/html');
        responseHeaders.set('Cross-Origin-Embedder-Policy', 'require-corp');
        responseHeaders.set('Cross-Origin-Opener-Policy', 'same-origin');

        // Write opening HTML before piping React content
        passthrough.write(htmlStart);
        pipe(passthrough);

        // Convert Node stream to Web ReadableStream
        const body = new ReadableStream({
          start(controller) {
            passthrough.on('data', (chunk) => {
              controller.enqueue(typeof chunk === 'string' ? new TextEncoder().encode(chunk) : new Uint8Array(chunk));
            });
            passthrough.on('end', () => {
              controller.enqueue(new TextEncoder().encode(htmlEnd));
              controller.close();
            });
            passthrough.on('error', (err) => {
              controller.error(err);
            });
          },
          cancel() {
            passthrough.destroy();
          },
        });

        resolve(
          new Response(body, {
            headers: responseHeaders,
            status: responseStatusCode,
          }),
        );
      },
      onShellError(error: unknown) {
        reject(error);
      },
      onError(error: unknown) {
        responseStatusCode = 500;

        if (shellRendered) {
          console.error(error);
        }
      },
    });

    setTimeout(abort, ABORT_DELAY);
  });
}

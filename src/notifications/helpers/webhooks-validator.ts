// import { createHmac } from 'node:crypto';
//@ts-ignore TS7034: Variable 'createHmac' implicitly has type 'any' in some locations where its type cannot be determined.
let createHmac;
(async () => {
  const { createHmac: cryptoCreateHmac } = await import('node:crypto');
  createHmac = cryptoCreateHmac;
})();

interface ParsedHeaders {
  ts: number;
  h1: string;
}
export class WebhooksValidator {
  private static readonly MAX_VALID_TIME_DIFFERENCE = 5;
  private extractHeader(header: string): ParsedHeaders {
    const parts = header.split(';');
    let ts = '';
    let h1 = '';
    for (const part of parts) {
      const [key, value] = part.split('=');
      if (value) {
        if (key === 'ts') {
          ts = value;
        } else if (key === 'h1') {
          h1 = value;
        }
      }
    }
    if (ts && h1) {
      return { ts: parseInt(ts), h1 };
    } else {
      throw new Error('[Paddle] Invalid webhook signature');
    }
  }

  public isValidSignature(requestBody: string, secretKey: string, signature: string) {
    const headers = this.extractHeader(signature);
    const payloadWithTime = `${headers.ts}:${requestBody}`;

    if (new Date().getTime() > new Date((headers.ts + WebhooksValidator.MAX_VALID_TIME_DIFFERENCE) * 1000).getTime()) {
      return false;
    }

    // @ts-ignore TS7005: Variable 'createHmac' implicitly has an 'any' type.
    if (!createHmac) throw new Error('createHmac not initialized');
    const hmac = createHmac('sha256', secretKey);
    hmac.update(payloadWithTime);

    const computedHash = hmac.digest('hex');
    return computedHash === headers.h1;
  }
}

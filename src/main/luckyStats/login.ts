import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import { createServer, Server } from 'http';
import { AddressInfo } from 'net';

export const LOGIN_SCOPE = 'game-data:upload game-data:status';
const CALLBACK = '/lucky-stats/callback';
type Phase =
  | 'idle'
  | 'waiting'
  | 'connecting'
  | 'connected'
  | 'cancelled'
  | 'failed';
export type LoginStatus = { state: Phase; message?: string };
export type LoginDependencies = {
  openBrowser: (url: string) => Promise<void>;
  connect: (key: string, current: () => boolean) => Promise<void>;
  request?: typeof fetch;
  timeoutMs?: number;
};

// Only the main process sees the verifier, authorization code, or credential.
export default class LuckyLogin {
  private result: LoginStatus = { state: 'idle' };

  private generation = 0;

  private server?: Server;

  private timer?: ReturnType<typeof setTimeout>;

  private abort?: AbortController;

  // eslint-disable-next-line no-useless-constructor, no-empty-function
  constructor(private deps: LoginDependencies) {}

  status(): LoginStatus {
    return { ...this.result };
  }

  cancel() {
    this.generation += 1;
    this.abort?.abort();
    this.close();
    this.result = { state: 'cancelled' };
  }

  private close() {
    clearTimeout(this.timer);
    this.server?.close();
    this.server?.closeAllConnections();
    this.server = undefined;
  }

  async start() {
    this.cancel();
    const { generation } = this;
    const current = () => generation === this.generation;
    const state = randomBytes(32).toString('base64url');
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const abort = new AbortController();
    this.abort = abort;
    this.result = { state: 'waiting' };
    let redirect = '';
    const fail = (message: string) => {
      if (current()) {
        this.result = { state: 'failed', message };
        this.close();
      }
    };
    const exchange = async (code: string) => {
      const requestTimer = setTimeout(() => abort.abort(), 60000);
      try {
        const response = await (this.deps.request || fetch)(
          'https://luckystats.gg/api/integrations/desktop/token',
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              Accept: 'application/json',
            },
            body: new URLSearchParams({
              grant_type: 'authorization_code',
              client_id: 'replay-reporter',
              redirect_uri: redirect,
              code,
              code_verifier: verifier,
            }).toString(),
            redirect: 'error',
            signal: abort.signal,
          },
        );
        if (!current()) return;
        if (response.headers.get('x-vercel-mitigated') === 'challenge') {
          fail(
            'Lucky Stats is blocking desktop login. Contact Lucky Stats support.',
          );
          return;
        }
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          const messages: Record<string, string> = {
            key_limit_reached:
              'Revoke an unused key in Lucky Stats Account → API keys, then try again.',
            invalid_grant: 'Login expired. Start a new login.',
            invalid_client: 'Lucky Stats has disabled this app connection.',
          };
          fail(
            messages[data.error] ||
              'Login could not be completed. Please try again.',
          );
          return;
        }
        if (
          data.token_type !== 'Bearer' ||
          typeof data.access_token !== 'string' ||
          !/^l7u_[a-f0-9]{64}$/.test(data.access_token) ||
          typeof data.scope !== 'string' ||
          !LOGIN_SCOPE.split(' ').every((scope) =>
            data.scope.split(' ').includes(scope),
          )
        ) {
          fail('Lucky Stats returned an invalid connection. Please try again.');
          return;
        }
        if (!current()) return;
        await this.deps.connect(data.access_token, current);
        if (current()) this.result = { state: 'connected' };
      } catch {
        fail(
          'Could not connect Lucky Stats. Check your connection and OS credential store, then try again.',
        );
      } finally {
        clearTimeout(requestTimer);
        if (current()) this.close();
      }
    };
    const server = createServer((req, res) => {
      let url: URL;
      try {
        url = new URL(req.url || '/', 'http://127.0.0.1');
      } catch {
        res.writeHead(400, {
          'Content-Type': 'text/plain',
          'Cache-Control': 'no-store',
        });
        res.end('Invalid login callback.');
        return;
      }
      const callbackState = url.searchParams.getAll('state');
      const codes = url.searchParams.getAll('code');
      const errors = url.searchParams.getAll('error');
      const denied =
        errors.length === 1 && errors[0] === 'access_denied' && !codes.length;
      const validCode =
        codes.length === 1 && /^[a-f0-9]{64}$/.test(codes[0]) && !errors.length;
      const valid =
        current() &&
        this.result.state === 'waiting' &&
        req.method === 'GET' &&
        req.socket.remoteAddress === '127.0.0.1' &&
        req.headers.host === new URL(redirect).host &&
        req.url?.startsWith(`${CALLBACK}?`) &&
        url.pathname === CALLBACK &&
        callbackState.length === 1 &&
        Buffer.byteLength(callbackState[0]) === Buffer.byteLength(state) &&
        timingSafeEqual(Buffer.from(callbackState[0]), Buffer.from(state)) &&
        (denied || validCode);
      res.writeHead(valid ? 200 : 400, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
      });
      res.end(
        valid
          ? 'Return to Replay Reporter to check your connection.'
          : 'Invalid login callback.',
      );
      if (!valid) return;
      if (denied) {
        this.result = { state: 'cancelled' };
        this.close();
      } else {
        this.result = { state: 'connecting' };
        server.close();
        exchange(codes[0]);
      }
    });
    this.server = server;
    server.headersTimeout = 3000;
    server.requestTimeout = 3000;
    server.on('connection', (socket) =>
      socket.setTimeout(3000, () => socket.destroy()),
    );
    try {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
      });
      if (!current()) {
        server.close();
        return;
      }
      redirect = `http://127.0.0.1:${
        (server.address() as AddressInfo).port
      }${CALLBACK}`;
      this.timer = setTimeout(() => {
        if (current()) {
          fail('Login timed out. Please start again.');
          this.generation += 1;
          abort.abort();
        }
      }, this.deps.timeoutMs ?? 300000);
      this.timer.unref();
      const params = new URLSearchParams({
        client_id: 'replay-reporter',
        response_type: 'code',
        scope: LOGIN_SCOPE,
        redirect_uri: redirect,
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
      await this.deps.openBrowser(
        `https://luckystats.gg/account/connect?${params}`,
      );
    } catch {
      fail(
        'Could not open browser login. Please try again or use an upload key.',
      );
    }
  }
}

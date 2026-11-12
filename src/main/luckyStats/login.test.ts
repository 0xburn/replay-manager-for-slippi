/** @jest-environment node */
/* eslint-disable no-await-in-loop, no-restricted-syntax */
import { createHash } from 'crypto';
import { request } from 'http';
import LuckyLogin, { LOGIN_SCOPE } from './login';

const token = `l7u_${'a'.repeat(64)}`;
let login: LuckyLogin;
let opened: URL;
let connect: jest.Mock;
let exchange: jest.Mock;
const waitFor = async (check: () => boolean) => {
  for (let n = 0; n < 100 && !check(); n += 1)
    await new Promise((resolve) => {
      setTimeout(resolve, 10);
    });
  expect(check()).toBe(true);
};
const callback = async (
  changes: Record<string, string> = {},
  host: string | undefined = undefined,
) => {
  const url = new URL(opened.searchParams.get('redirect_uri')!);
  url.searchParams.set('state', opened.searchParams.get('state')!);
  url.searchParams.set('code', 'b'.repeat(64));
  Object.entries(changes).forEach(([key, value]) =>
    url.searchParams.set(key, value),
  );
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = request(url, { headers: host ? { Host: host } : {} }, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () => resolve({ status: res.statusCode!, body }));
    });
    req.on('error', reject);
    req.end();
  });
};
beforeEach(() => {
  connect = jest.fn(async () => {});
  exchange = jest.fn(
    async () =>
      new Response(
        JSON.stringify({
          access_token: token,
          token_type: 'Bearer',
          scope: LOGIN_SCOPE,
        }),
      ),
  );
  login = new LuckyLogin({
    openBrowser: async (url) => {
      opened = new URL(url);
    },
    connect,
    request: exchange,
  });
});
afterEach(() => login.cancel());
it('uses S256, a loopback listener and a one-shot exchange with no secrets in status/callback', async () => {
  await login.start();
  expect(opened.origin).toBe('https://luckystats.gg');
  expect(opened.searchParams.get('client_id')).toBe('replay-reporter');
  expect(opened.searchParams.get('code_challenge_method')).toBe('S256');
  const result = await callback();
  expect(result.status).toBe(200);
  await waitFor(() => login.status().state === 'connected');
  const options = exchange.mock.calls[0][1];
  const body = new URLSearchParams(options.body);
  expect(body.get('redirect_uri')).toBe(
    opened.searchParams.get('redirect_uri'),
  );
  expect(
    createHash('sha256').update(body.get('code_verifier')!).digest('base64url'),
  ).toBe(opened.searchParams.get('code_challenge'));
  expect(options.redirect).toBe('error');
  expect(body.has('client_secret')).toBe(false);
  expect(connect.mock.calls[0][0]).toBe(token);
  expect(JSON.stringify(login.status()) + result.body).not.toContain(token);
  expect(exchange).toHaveBeenCalledTimes(1);
});
it('rejects wrong state, rebinding hosts and malformed codes without consuming login', async () => {
  await login.start();
  for (const [changes, host] of [
    [{ state: 'wrong' }, undefined],
    [{}, 'evil.example'],
    [{ code: 'invalid' }, undefined],
  ] as const)
    expect((await callback(changes, host)).status).toBe(400);
  expect(exchange).not.toHaveBeenCalled();
  expect((await callback()).status).toBe(200);
  await waitFor(() => login.status().state === 'connected');
});
it('cancellation during exchange cannot install a late credential', async () => {
  let finish!: (response: Response) => void;
  exchange.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  await login.start();
  await callback();
  await waitFor(() => exchange.mock.calls.length === 1);
  login.cancel();
  finish(
    new Response(
      JSON.stringify({
        access_token: token,
        token_type: 'Bearer',
        scope: LOGIN_SCOPE,
      }),
    ),
  );
  await new Promise((resolve) => {
    setTimeout(resolve, 30);
  });
  expect(connect).not.toHaveBeenCalled();
  expect(login.status().state).toBe('cancelled');
});
it('reports a firewall challenge without reflecting its response body', async () => {
  exchange.mockResolvedValue(
    new Response('sensitive firewall body', {
      status: 429,
      headers: { 'x-vercel-mitigated': 'challenge' },
    }),
  );
  await login.start();
  await callback();
  await waitFor(() => login.status().state === 'failed');
  expect(login.status().message).toContain('blocking desktop login');
  expect(login.status().message).not.toContain('sensitive');
  expect(connect).not.toHaveBeenCalled();
});
it('rejects credentials for Zekku scopes', async () => {
  exchange.mockResolvedValue(
    new Response(
      JSON.stringify({
        access_token: token,
        token_type: 'Bearer',
        scope: 'personal:upload personal:status',
      }),
    ),
  );
  await login.start();
  await callback();
  await waitFor(() => login.status().state === 'failed');
  expect(connect).not.toHaveBeenCalled();
});
it('expires the listener without exchanging a code', async () => {
  login = new LuckyLogin({
    openBrowser: async (url) => {
      opened = new URL(url);
    },
    connect,
    request: exchange,
    timeoutMs: 30,
  });
  await login.start();
  await waitFor(() => login.status().state === 'failed');
  expect(login.status().message).toContain('timed out');
  expect(exchange).not.toHaveBeenCalled();
});

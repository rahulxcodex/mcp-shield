import { DashboardServer } from '../../src/dashboard/server';
import * as http from 'http';

describe('DashboardServer Cookie Session & URL Token Protection', () => {
  let server: DashboardServer;
  let port: number;
  let token: string;

  beforeAll(async () => {
    server = new DashboardServer(0);
    port = await server.start();
    token = server.getAuthToken();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('DASH-01: Query string token sets HttpOnly cookie and redirects (302) to strip token from URL', async () => {
    await new Promise<void>((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: `/?token=${token}`,
          method: 'GET'
        },
        (res) => {
          expect(res.statusCode).toBe(302);
          expect(res.headers.location).toBe('/');
          const setCookie = res.headers['set-cookie'];
          expect(setCookie).toBeDefined();
          expect(setCookie![0]).toContain('mcp_shield_session=');
          expect(setCookie![0]).toContain('HttpOnly');
          expect(setCookie![0]).toContain('SameSite=Strict');
          resolve();
        }
      );
      req.on('error', reject);
      req.end();
    });
  });

  it('DASH-02: Cookie-authenticated request to / succeeds without token in query string', async () => {
    await new Promise<void>((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/',
          method: 'GET',
          headers: {
            Cookie: `mcp_shield_session=${token}`
          }
        },
        (res) => {
          expect(res.statusCode).toBe(200);
          expect(res.headers['content-type']).toContain('text/html');
          resolve();
        }
      );
      req.on('error', reject);
      req.end();
    });
  });

  it('DASH-03: Unauthorized request without valid cookie or token is rejected (401)', async () => {
    await new Promise<void>((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/',
          method: 'GET'
        },
        (res) => {
          expect(res.statusCode).toBe(401);
          resolve();
        }
      );
      req.on('error', reject);
      req.end();
    });
  });
});

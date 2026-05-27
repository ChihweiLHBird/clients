import { mock } from "jest-mock-extended";
import type { Context, Next } from "koa";

import { LogService } from "@bitwarden/common/platform/abstractions/log.service";

import { buildOriginProtectionMiddleware } from "./serve.command";

describe("buildOriginProtectionMiddleware", () => {
  const logService = mock<LogService>();
  const allowedHosts = new Set(["localhost:8087", "127.0.0.1:8087", "[::1]:8087"]);
  const middleware = buildOriginProtectionMiddleware({
    protectOrigin: true,
    allowedHosts,
    logService,
  });

  describe("when protectOrigin is true (default)", () => {
    // Probe 1: classical cross-origin fetch — Origin present, Host allowlisted
    it("probe 1: blocks request with a non-empty Origin header (cross-origin fetch)", async () => {
      const ctx = mock<Context>({ headers: { host: "127.0.0.1:8087", origin: "https://evil.example" } });
      const next = jest.fn<Promise<void>, []>();

      await middleware(ctx, next as unknown as Next);

      expect(ctx.status).toBe(403);
      expect(next).not.toHaveBeenCalled();
    });

    // Probe 2: legitimate same-origin GET — no Origin, Host on allowlist
    it("probe 2: allows request with no Origin header and allowlisted Host", async () => {
      const ctx = mock<Context>({ headers: { host: "127.0.0.1:8087", origin: undefined } });
      const next = jest.fn<Promise<void>, []>().mockResolvedValue(undefined);

      await middleware(ctx, next as unknown as Next);

      expect(next).toHaveBeenCalled();
      expect(ctx.status).not.toBe(403);
    });

    // Probe 3: DNS-rebind simulation — no Origin, Host NOT on allowlist
    it("probe 3: blocks DNS-rebound request with disallowed Host and no Origin (THE FIX)", async () => {
      const ctx = mock<Context>({ headers: { host: "evil.example:8087", origin: undefined } });
      const next = jest.fn<Promise<void>, []>();

      await middleware(ctx, next as unknown as Next);

      expect(ctx.status).toBe(403);
      expect(next).not.toHaveBeenCalled();
    });

    // Probe 4: empty-string Origin header
    it("probe 4: blocks request with empty-string Origin header", async () => {
      const ctx = mock<Context>({ headers: { host: "127.0.0.1:8087", origin: "" } });
      const next = jest.fn<Promise<void>, []>();

      await middleware(ctx, next as unknown as Next);

      expect(ctx.status).toBe(403);
      expect(next).not.toHaveBeenCalled();
    });

    it("allows request from localhost:PORT with no Origin", async () => {
      const ctx = mock<Context>({ headers: { host: "localhost:8087", origin: undefined } });
      const next = jest.fn<Promise<void>, []>().mockResolvedValue(undefined);

      await middleware(ctx, next as unknown as Next);

      expect(next).toHaveBeenCalled();
    });

    it("allows request from [::1]:PORT with no Origin", async () => {
      const ctx = mock<Context>({ headers: { host: "[::1]:8087", origin: undefined } });
      const next = jest.fn<Promise<void>, []>().mockResolvedValue(undefined);

      await middleware(ctx, next as unknown as Next);

      expect(next).toHaveBeenCalled();
    });

    it("blocks request with missing Host header (no host key)", async () => {
      const ctx = mock<Context>({ headers: {} });
      const next = jest.fn<Promise<void>, []>();

      await middleware(ctx, next as unknown as Next);

      expect(ctx.status).toBe(403);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("when protectOrigin is false (--disable-origin-protection)", () => {
    it("passes through any request regardless of headers", async () => {
      const passThrough = buildOriginProtectionMiddleware({
        protectOrigin: false,
        allowedHosts,
        logService,
      });
      const ctx = mock<Context>({ headers: { host: "evil.example:8087", origin: "https://evil.example" } });
      const next = jest.fn<Promise<void>, []>().mockResolvedValue(undefined);

      await passThrough(ctx, next as unknown as Next);

      expect(next).toHaveBeenCalled();
    });
  });
});

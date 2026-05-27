import http from "node:http";
import net from "node:net";

import { Router } from "@koa/router";
import { OptionValues } from "commander";
import * as koa from "koa";
import type { Context, Next } from "koa";
import * as koaBodyParser from "koa-bodyparser";
import * as koaJson from "koa-json";

import { LogService } from "@bitwarden/common/platform/abstractions/log.service";
import { Utils } from "@bitwarden/common/platform/misc/utils";

import { OssServeConfigurator } from "../oss-serve-configurator";
import { ServiceContainer } from "../service-container/service-container";

export function buildOriginProtectionMiddleware(opts: {
  protectOrigin: boolean;
  allowedHosts: ReadonlySet<string>;
  logService: LogService;
}): (ctx: Context, next: Next) => Promise<void> {
  return async (ctx, next) => {
    if (opts.protectOrigin) {
      // Layer 1: Host allowlist. Catches DNS-rebinding (no Origin header
      // present — same-origin GET per Fetch spec — but Host reveals the
      // attacker's rebound domain). Must run before the Origin check because
      // DNS-rebound requests omit Origin entirely and would otherwise pass.
      if (!opts.allowedHosts.has(ctx.headers.host ?? "")) {
        ctx.status = 403;
        opts.logService.warning(
          `Blocking request with disallowed Host "${ctx.headers.host ?? "(missing)"}"`,
        );
        return;
      }
      // Layer 2: Origin check (defense-in-depth). Catches classical
      // cross-origin fetches and sandboxed-iframe attacks that send
      // Origin: null. Using !== (strict) to reject any defined Origin value
      // including the empty string, for consistency with the Host check.
      if (ctx.headers.origin !== undefined) {
        ctx.status = 403;
        opts.logService.warning(
          `Blocking request from "${
            Utils.isNullOrEmpty(ctx.headers.origin)
              ? "(Origin header value missing)"
              : ctx.headers.origin
          }"`,
        );
        return;
      }
    }
    await next();
  };
}

export class ServeCommand {
  constructor(
    protected serviceContainer: ServiceContainer,
    protected serveConfigurator: OssServeConfigurator,
  ) {}

  async run(options: OptionValues) {
    const protectOrigin = !options.disableOriginProtection;
    const port = options.port || 8087;
    const hostname = options.hostname || "localhost";
    this.serviceContainer.logService.info(
      `Starting server on ${hostname}:${port} with ${
        protectOrigin ? "origin protection" : "no origin protection"
      }`,
    );

    // Allowlist of Host header values that identify legitimate same-origin
    // requests to the loopback interface. Any other Host value indicates a
    // DNS-rebinding attack (the browser has rebound an attacker-controlled
    // name to 127.0.0.1/::1 and is sending the attacker's hostname in Host).
    const ALLOWED_HOSTS = new Set([`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`]);

    const server = new koa();
    const router = new Router();
    process.env.BW_SERVE = "true";
    process.env.BW_NOINTERACTION = "true";

    server
      .use(
        buildOriginProtectionMiddleware({
          protectOrigin,
          allowedHosts: ALLOWED_HOSTS,
          logService: this.serviceContainer.logService,
        }),
      )
      .use(koaBodyParser())
      .use(koaJson({ pretty: false, param: "pretty" }));

    await this.serveConfigurator.configureRouter(router);

    server.use(router.routes()).use(router.allowedMethods());

    if (hostname.startsWith("fd+connected://")) {
      const fd = parseInt(hostname.slice("fd+connected://".length));
      const httpServer = http.createServer(server.callback());
      const socket = new net.Socket({ fd: fd, readable: true, writable: true });
      // allow idle sockets, incomplete handshakes and slow requests
      httpServer.keepAliveTimeout = 0;
      httpServer.headersTimeout = 0;
      httpServer.timeout = 0;
      socket.pause();
      httpServer.emit("connection", socket);
      socket.resume(); // Let the HTTP parser start reading
    } else if (hostname.startsWith("fd+listening://")) {
      const fd = parseInt(hostname.slice("fd+listening://".length));
      server.listen({ fd }, () => {
        this.serviceContainer.logService.info("Listening on " + hostname);
      });
    } else if (hostname.startsWith("unix://")) {
      const socketPath = hostname.slice("unix://".length);
      server.listen(socketPath, () => {
        this.serviceContainer.logService.info("Listening on " + hostname);
      });
    } else {
      server.listen(port, hostname === "all" ? null : hostname, () => {
        this.serviceContainer.logService.info("Listening on " + hostname + ":" + port);
      });
    }
  }
}

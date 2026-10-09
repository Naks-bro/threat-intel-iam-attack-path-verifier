import { afterEach, describe, expect, it, vi } from "vitest";
import { FoundryApiError, getFoundryOverview, getFoundryRule } from "./foundry-api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("foundry API boundary", () => {
  it("returns the correlation id with a valid response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            database: "available",
            database_detail: "current",
            storage: "postgres",
            registry: "empty",
            sources: [],
            run: null,
            primitives: [],
            relations: [],
            candidates: [],
          }),
          { status: 200, headers: { "X-Request-ID": "request-01" } },
        ),
      ),
    );

    const result = await getFoundryOverview();

    expect(result.data.registry).toBe("empty");
    expect(result.requestId).toBe("request-01");
  });

  it("normalizes FastAPI error details without exposing arbitrary response bodies", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "database_unavailable", secret: "ignored" }), {
          status: 503,
          headers: { "X-Request-ID": "request-02" },
        }),
      ),
    );

    await expect(getFoundryOverview()).rejects.toEqual(
      expect.objectContaining<Partial<FoundryApiError>>({
        status: 503,
        code: "database_unavailable",
        requestId: "request-02",
      }),
    );
  });

  it("represents a missing immutable rule as an empty result", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "rule_not_found" }), {
          status: 404,
          headers: { "X-Request-ID": "request-03" },
        }),
      ),
    );

    await expect(getFoundryRule("version_missing")).resolves.toEqual({
      data: null,
      requestId: "request-03",
    });
  });
});

# github-core-clone-01 — a standalone GitHub-compatible git forge

One Node 22 process, standard library only, no git binary, no network, no UI.
It serves four surfaces from its own in-memory store:

- **git smart HTTP** — upload-pack protocol v2 (+ v0 fallback) and receive-pack
  v0 at `/{owner}/{repo}.git`, with a real PACK v2 reader/writer (full objects,
  no deltas; OFS/REF deltas are accepted on push)
- **REST v3** — repositories, branches, commits, contents, labels, issues,
  comments and pull requests under `/api/v3`
- **GraphQL v4** — `POST /api/graphql`, with a small real GraphQL
  parser/executor for the documents `gh` and `github-mcp-server` send
- **MCP** — `POST /mcp`, JSON-RPC 2.0 over Streamable HTTP (modern
  `server/discover` era, legacy `initialize` fallback), six tools that act on
  the same store as REST

## Run it

```sh
node --experimental-strip-types main.ts
```

The lifecycle: bind an ephemeral port, `POST {"port": N}` to
`$MAKEFUN_ENV_URL/register`, long-poll `GET $MAKEFUN_ENV_URL/done` until it
says `{"done": true}`, then exit 0. With `FORGE_STANDALONE=1` and no
`MAKEFUN_ENV_URL`, it just serves (local practice only).

## Determinism

Every timestamp comes from one logical clock seeded from `MAKEFUN_TRIAL_NOW`
(or the fixed 2025-01-01 epoch) and advanced one second per mutation. There
is no wall clock and no unseeded randomness in any response, so two runs over
the same requests answer byte-identically.

The token's owner is the scenario viewer from the kit's fixed public seed
(`SCENARIO_SEED 6a09e667f3bcc909` → `adaiversen`); every repository belongs to
that login, and any other owner is a 404, never a 403.

## Layout

- `main.ts` — the whole forge: lifecycle, store, git objects/packs, REST,
  GraphQL and MCP
- `package.json`, `tsconfig.json`, `LICENSE` (MIT)

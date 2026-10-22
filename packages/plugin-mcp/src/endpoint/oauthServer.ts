import type {
  OAuthClientInformationFull,
  OAuthTokens,
  OpenIdProviderDiscoveryMetadata,
} from '@modelcontextprotocol/server'
import type { Endpoint, PayloadHandler, PayloadRequest } from 'payload'

import { OAuthErrorCode } from '@modelcontextprotocol/server'
import { createHash } from 'crypto'
import { APIError, createAuthToken } from 'payload'
import { formatAdminURL } from 'payload/shared'

import type { MCPBuiltinOAuthConfig } from '../types.js'

import { getPluginConfig } from '../utils/getPluginConfig.js'
import { getMCPURL } from './oauth.js'

type Client = { name: string; redirectURIs: string[] }

type Consent = {
  clientID: string
  codeChallenge: string
  collection: string
  redirectURI: string
  state: null | string
  userID: number | string
}

type Code = {
  accessToken: string
  clientID: string
  codeChallenge: string
  expiresIn?: number
  redirectURI: string
}

/**
 * Turns Payload into the OAuth authorization server for MCP clients when `oauth.type` is
 * `'builtin'`. Clients register, the user allows them after logging in to the admin panel, and
 * the client receives the access token `issueToken` creates.
 *
 * Clients, consent forms, and authorization codes are encrypted and handed to the client instead
 * of being stored, so nothing is written to the database.
 */
export const oauthServerEndpoints: Endpoint[] = [
  {
    disableAuth: true,
    handler: (req) => withIssuer(req, (issuer) => metadataResponse(issuer)),
    method: 'get',
    // OpenID discovery is the only metadata location MCP clients check below the issuer's path,
    // which lets this work under /api without a route at the site root
    path: '/mcp/oauth/.well-known/openid-configuration',
  },
  {
    disableAuth: true,
    handler: (req) => withIssuer(req, () => Response.json({ keys: [] })),
    method: 'get',
    path: '/mcp/oauth/jwks',
  },
  {
    disableAuth: true,
    handler: (req) => withIssuer(req, () => register(req)),
    method: 'post',
    path: '/mcp/oauth/register',
  },
  {
    handler: (req) => withIssuer(req, () => authorize(req)),
    method: 'get',
    path: '/mcp/oauth/authorize',
  },
  {
    handler: (req) => withIssuer(req, () => approve(req)),
    method: 'post',
    path: '/mcp/oauth/authorize',
  },
  {
    disableAuth: true,
    handler: (req) => withIssuer(req, () => token(req)),
    method: 'post',
    path: '/mcp/oauth/token',
  },
]

/** The authorization server URL, or `undefined` when Payload isn't the authorization server. */
const getIssuer = (req: PayloadRequest): string | undefined =>
  getPluginConfig({ config: req.payload.config }).oauth?.type === 'builtin'
    ? `${getMCPURL({ config: req.payload.config, url: req.url! })}/oauth`
    : undefined

const withIssuer = (
  req: PayloadRequest,
  handler: (issuer: string) => Promise<Response> | Response,
): Promise<Response> | Response => {
  const issuer = getIssuer(req)
  return issuer ? handler(issuer) : new Response(null, { status: 404 })
}

const metadataResponse = (issuer: string): Response =>
  Response.json(
    {
      authorization_endpoint: `${issuer}/authorize`,
      code_challenge_methods_supported: ['S256'],
      grant_types_supported: ['authorization_code'],
      // Required by OpenID discovery. No ID tokens are issued.
      id_token_signing_alg_values_supported: ['RS256'],
      issuer,
      jwks_uri: `${issuer}/jwks`,
      registration_endpoint: `${issuer}/register`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      token_endpoint: `${issuer}/token`,
      token_endpoint_auth_methods_supported: ['none'],
    } satisfies OpenIdProviderDiscoveryMetadata,
    { headers: { 'Access-Control-Allow-Origin': '*' } },
  )

const register: PayloadHandler = async (req) => {
  const { client_name, redirect_uris } = await req.json!().catch(() => ({}))

  if (
    !Array.isArray(redirect_uris) ||
    !redirect_uris.length ||
    !redirect_uris.every(
      (uri) => typeof uri === 'string' && URL.canParse(uri) && !uri.includes('#'),
    )
  ) {
    return Response.json({ error: OAuthErrorCode.InvalidRedirectUri }, { status: 400 })
  }

  const client: Client = {
    name: typeof client_name === 'string' ? client_name : 'An MCP client',
    redirectURIs: redirect_uris,
  }

  return Response.json(
    {
      client_id: seal({ type: 'client', data: client, req }),
      client_name: client.name,
      grant_types: ['authorization_code'],
      redirect_uris: client.redirectURIs,
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    } satisfies OAuthClientInformationFull,
    { status: 201 },
  )
}

const authorize: PayloadHandler = (req) => {
  const url = new URL(req.url!)
  const params = url.searchParams
  const clientID = params.get('client_id')
  const client = unseal<Client>({ type: 'client', req, value: clientID })
  const redirectURI = params.get('redirect_uri')

  // Never redirect to an address the client didn't register
  if (!client || !redirectURI || !client.redirectURIs.includes(redirectURI)) {
    return page({
      content: '<p>Start the sign-in again from your MCP client.</p>',
      status: 400,
      title: 'This sign-in link is invalid',
    })
  }

  const state = params.get('state')
  const codeChallenge = params.get('code_challenge')

  if (
    params.get('response_type') !== 'code' ||
    params.get('code_challenge_method') !== 'S256' ||
    !codeChallenge
  ) {
    return redirect({ params: { error: OAuthErrorCode.InvalidRequest, state }, redirectURI })
  }

  if (!req.user) {
    const loginURL = formatAdminURL({ adminRoute: req.payload.config.routes.admin, path: '/login' })

    return new Response(null, {
      headers: {
        Location: `${loginURL}?redirect=${encodeURIComponent(url.pathname + url.search)}`,
      },
      status: 302,
    })
  }

  const consent: Consent = {
    clientID: clientID!,
    codeChallenge,
    collection: req.user.collection,
    redirectURI,
    state,
    userID: req.user.id,
  }

  return page({
    content: `<p>It will be able to use this app's MCP tools as ${escapeHTML(String(req.user.email ?? req.user.id))}, and you will return to ${escapeHTML(new URL(redirectURI).host || redirectURI)}.</p>
<form method="post">
<input name="consent" type="hidden" value="${seal({ type: 'consent', data: consent, expiresIn: 20 * 60 * 60, req })}">
<button name="decision" type="submit" value="allow">Allow</button>
<button name="decision" type="submit" value="deny">Deny</button>
</form>`,
    status: 200,
    title: `Allow ${client.name} to use your account?`,
  })
}

const approve: PayloadHandler = async (req) => {
  const form = new URLSearchParams(await req.text!())
  const consent = unseal<Consent>({ type: 'consent', req, value: form.get('consent') })

  // The form is only valid for the user it was shown to
  if (!consent || req.user?.id !== consent.userID || req.user.collection !== consent.collection) {
    return page({
      content: '<p>Start the sign-in again from your MCP client.</p>',
      status: 400,
      title: 'This sign-in request expired',
    })
  }

  const { clientID, codeChallenge, redirectURI, state } = consent

  if (form.get('decision') !== 'allow') {
    return redirect({ params: { error: OAuthErrorCode.AccessDenied, state }, redirectURI })
  }

  const { issueToken = issueLoginToken } = getPluginConfig({ config: req.payload.config })
    .oauth as MCPBuiltinOAuthConfig
  const { accessToken, expiresIn } = await issueToken({ req })

  const code: Code = { accessToken, clientID, codeChallenge, expiresIn, redirectURI }

  return redirect({
    params: { code: seal({ type: 'code', data: code, expiresIn: 60, req }), state },
    redirectURI,
  })
}

const token: PayloadHandler = async (req) => {
  const form = new URLSearchParams(await req.text!())
  const code = unseal<Code>({ type: 'code', req, value: form.get('code') })

  if (
    form.get('grant_type') !== 'authorization_code' ||
    !code ||
    code.clientID !== form.get('client_id') ||
    code.redirectURI !== form.get('redirect_uri') ||
    // PKCE: only the client that started the sign-in knows the verifier
    createHash('sha256')
      .update(form.get('code_verifier') ?? '')
      .digest('base64url') !== code.codeChallenge
  ) {
    return Response.json({ error: OAuthErrorCode.InvalidGrant }, { status: 400 })
  }

  return Response.json(
    {
      access_token: code.accessToken,
      expires_in: code.expiresIn,
      token_type: 'Bearer',
    } satisfies OAuthTokens,
    { headers: { 'Cache-Control': 'no-store' } },
  )
}

/** The default `issueToken`: a Payload login token, which Payload's JWT strategy accepts. */
const issueLoginToken: NonNullable<MCPBuiltinOAuthConfig['issueToken']> = async ({ req }) => {
  const collection = req.payload.collections[req.user!.collection]!

  if (collection.config.auth.disableLocalStrategy) {
    throw new APIError(
      `The "${collection.config.slug}" collection has its local strategy disabled, so MCP clients can't get Payload login tokens for it. Pass oauth.issueToken to the MCP plugin.`,
    )
  }

  // The full document, like the one a password login starts the session on
  const user = (await req.payload.db.findOne<NonNullable<PayloadRequest['user']>>({
    collection: collection.config.slug,
    req,
    where: { id: { equals: req.user!.id } },
  }))!

  const { token } = await createAuthToken({
    collectionConfig: collection.config,
    email: user.email!,
    req,
    user,
  })

  return { accessToken: token, expiresIn: collection.config.auth.tokenExpiration }
}

/**
 * Encrypts data for the client to hold, so it doesn't need to be stored. `type` keeps one kind
 * from being used as another, e.g. a client ID as an authorization code.
 */
const seal = ({
  type,
  data,
  expiresIn,
  req,
}: {
  data: object
  /** Seconds */
  expiresIn?: number
  req: PayloadRequest
  type: string
}): string =>
  req.payload.encrypt(
    JSON.stringify({ ...data, type, exp: expiresIn && Date.now() + expiresIn * 1000 }),
  )

const unseal = <T>({
  type,
  req,
  value,
}: {
  req: PayloadRequest
  type: string
  value: null | string
}): T | undefined => {
  // Only the v1 format is authenticated. Older formats decrypt anything without an error.
  if (!value?.startsWith('v1:')) {
    return undefined
  }

  try {
    const data = JSON.parse(req.payload.decrypt(value))
    return data.type === type && (!data.exp || data.exp > Date.now()) ? data : undefined
  } catch {
    return undefined
  }
}

const redirect = ({
  params,
  redirectURI,
}: {
  params: Record<string, null | string>
  redirectURI: string
}): Response => {
  const location = new URL(redirectURI)

  for (const [key, value] of Object.entries(params)) {
    if (value) {
      location.searchParams.set(key, value)
    }
  }

  return new Response(null, { headers: { Location: location.href }, status: 302 })
}

const page = ({
  content,
  status,
  title,
}: {
  content: string
  status: number
  title: string
}): Response =>
  new Response(
    `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHTML(title)}</title>
<style>
body { font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 32rem; overflow-wrap: anywhere; padding: 0 1rem }
button { font: inherit; margin-inline-end: 0.5rem; padding: 0.5rem 1rem }
</style>
</head>
<body><h1>${escapeHTML(title)}</h1>${content}</body>
</html>`,
    {
      headers: {
        // Stop other sites from framing the page to trick users into clicking Allow
        'Content-Security-Policy': "frame-ancestors 'none'",
        'Content-Type': 'text/html; charset=utf-8',
      },
      status,
    },
  )

const escapeHTML = (value: string): string =>
  value.replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`)

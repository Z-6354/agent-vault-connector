# Public documentation research evidence

Research date: 2026-11-01. Scope: seven specified public documentation URLs. These are documentation claims, not compatibility or functional test results. Muse/Grok/Dot cloud accounts were absent; actual product connection, authentication, browser-session reuse, and export tests are **BLOCKED**.

No account authentication, credential/config/environment inspection, runtime API calls, or external messaging was performed. This file was saved after public research, at the coordinator's explicit request. No additional fetching was performed for this write-up.

## Actual fetch status

Each exact requested URL was submitted to WebFetch. Two subsequent batches of unauthenticated public HTTP GETs verified status and extracted text in memory. The first HTTP attempt used `python`, which was unavailable; it made no requests. The successful batches used `python3`, a fixed public user agent, no supplied authorization headers, no cookie jar, and `ProxyHandler({})`. No response files were saved. Redirects were followed by urllib's default behavior. Status and final URL below are from the actual successful first HTTP batch.

| Requested URL | HTTP result and final URL | Observed title / failure |
| --- | --- | --- |
| https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse | 200; same final URL | `How We Built Safety Into Muse \| Meta AI Research` |
| https://www.meta.com/help/artificial-intelligence/1687253048996149/ | 200; final https://www.meta.com/help/superintelligence/1687253048996149/ | `How Muse works with Connectors \| Meta Help Center \| Meta` |
| https://docs.x.ai/grok-bot/security | 200; same final URL | `Grok Bot security \| SpaceXSI Docs` |
| https://docs.x.ai/grok-bot/computer-and-apps | 200; same final URL | `Use the computer and apps \| SpaceXSI Docs` |
| https://help.openai.com/en/articles/20001529-dots-privacy-security-and-safety-faqs | **403 — BLOCKED**; same final URL | No title extracted. Body: `Enable JavaScript and cookies to continue` |
| https://github.com/example-org/private-repo/blob/<commit>/README.md | **404 — BLOCKED**; same final URL | `Page not found · GitHub · GitHub` |
| https://github.com/sanshanya/dsh-dot-mcp/blob/a6d4ddac3ca7ec1b0d2baf334f1df5f7d1a81a56/README.md | 200; same final URL | `dsh-dot-mcp/README.md at a6d4ddac3ca7ec1b0d2baf334f1df5f7d1a81a56 · sanshanya/dsh-dot-mcp · GitHub` |

For the OpenAI URL, WebFetch reported: “The server returned HTTP 403 Forbidden.” and “The response body was not retrieved.” For the Z-6354 README, WebFetch reported: “The server returned HTTP 404 Not Found.” and “The response body was not retrieved.” The public HTTP verification independently confirmed both status codes. A GitHub 404 does not distinguish private, nonexistent, or otherwise unavailable content. No authentication was attempted. Neither blocked page supplies verified product facts.

Other WebFetch calls returned content summaries, but some summaries disclaimed live retrieval. The independent HTTP status and text extraction below establish what was actually accessible. Header metadata such as ETag, Last-Modified, Date, and request IDs was not collected. Statuses are point-in-time observations, not availability guarantees.

## Muse

Source: https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse

### Identity, native connections, runtime and protocol

Under “An agent in your own cloud computer”:

> You and your Muse share your own dedicated computer in the cloud.

> Each Virtual Machine(VM) is an isolated linux box with a browser

Under “Connectors”:

> We’ve built an initial set of connectors to third-party systems and to other Meta apps like Instagram and Facebook.

> Muse can also write its own custom connectors for other services you care about if they have their own APIs or CLIs.

The article describes provider API integrations. APIs and CLIs here do not establish MCP support or compatibility with this project.

Under “Muse Secure VM”, the harness, workspace and tools:

> operate in a systemd-nspawn runtime container

> All communication between the runtime cell and other services in the VM happens via Unix domain sockets with SO_PEERCRED and peer ACLs.

### Credential storage and authentication

Under “Muse Secure VM” (source line breaks normalized):

> hatch-authd is responsible for credential storage (including OAuth tokens for third-party services you choose to connect – these are stored in your VM, not in centralized Meta infrastructure) and for credential surrogation so your main agent never sees sensitive credentials.

Under “Network egress”:

> Sentinel will replace any surrogate tokens with the real credential, obtained from authd, at the network boundary.

This documents authentication insertion at egress. It does not establish an external credential retrieval API.

### Browser login and reuse limits

Under “Browser”, the custom client UI captures username and password, routes them directly to authd, and stores them:

> in the secure credentials store outside the runtime cell in the Muse VM.

> What you enter goes straight to secure storage and is not visible to your main agent, but gets injected into the browser window at the point of need.

The separate broker:

> manages the Chrome DevTools Protocol connection

The article says the agent pauses during user takeover and secure credential filling. It documents saved-password injection, but does not explicitly document importing another browser's profile/cookies, sharing connector OAuth credentials with browser sessions, or moving authenticated sessions between runtimes.

### Export and migration limits

Under “Our Policy Around Data”:

> You can inspect, edit and download these files freely, including Muse’s memory about you. This extends to credentials and auth tokens for any third-party services you connect — they’re stored in a separate isolated container in your VM, not in other Meta services.

The same paragraph states that VM data is backed up continuously for restoration. Preserve the full “This extends” wording: it could be read broadly, so the evidence does not justify categorically excluding credential export. The article does not specify a credential export format, retrieval API, cookie/profile export procedure, VM image export, or cross-provider migration procedure.

### Meta Help Center connector details

Requested source: https://www.meta.com/help/artificial-intelligence/1687253048996149/

Observed final source: https://www.meta.com/help/superintelligence/1687253048996149/

Under “Meta Connectors”:

> Three of these – Facebook, Instagram and Threads – are connected automatically if you have your accounts in the same Accounts Center.

Accounts can be managed through Accounts Center. Setup includes:

> Tap Continue to authorize the connection.

> Follow any additional login or authorization steps.

Under “Custom connectors”:

> Muse will guide you through the process, which can involve retrieving API information from the service. Muse stores these in its Secure Credentials Store.

No more precise credential type, storage mechanism, or protocol is supplied there.

Under “To disconnect a Connector”:

> Disconnecting stops Muse from exchanging data with the Connector. Information that Muse previously used to perform tasks with that Connector might still remain in Muse’s memories and your conversation history.

The accessible help article provides no browser profile/session import or cross-runtime migration procedure.

## Grok Bot

Sources:

- https://docs.x.ai/grok-bot/security
- https://docs.x.ai/grok-bot/computer-and-apps

**Source identity caveat:** these x.ai-hosted pages are titled `SpaceXSI Docs` and literally refer to Cursor servers, accounts, infrastructure and connector backend. This branding mixture is observable in the fetched content. No explanation, product equivalence, or ownership/compatibility conclusion was verified.

### Identity and authentication

Security → “Identity and sign-ins”:

> Members sign in to Grok Bot with their Cursor account

The section names SAML 2.0 SSO and Enterprise-only SCIM 2.0 provisioning.

> A Bot has no identity or credentials of its own:

> Bots act as the signed-in member.

An explicit exception allows centrally configured integrations to use team or service-account credentials. Account SSO/provisioning is separate from browser sessions and does not establish their portability.

### Native app credential storage

Security → “Identity and sign-ins”:

> Connector tokens stay on Cursor's backend. Bots invoke tools without receiving OAuth tokens, and tokens are never stored on the computer.

Computer/apps → “Connect an app”:

> App logins stay off the computer. OAuth tokens are held on Cursor's connector backend, and the Bot invokes tools without receiving them.

These statements concern connector tokens. They should not be conflated with the browser's local authenticated state.

### Explicit same-account browser login reuse

Security:

> Application sessions persist only on the member's computer.

Security → “Data retention and deletion” (source line breaks normalized):

> Each member's computer keeps local files, browser sessions, and anything saved in the browser on a durable disk across sessions. Connector tokens are never stored on the computer.

Computer/apps → “One computer, shared by all your Bots”:

> Browser cookies and signed-in sessions are shared

> Command-line credentials are shared

> The computer is assigned to your user account, not an individual Bot.

Computer/apps → “Sign in once”:

> Browser sessions persist so you usually do not need to sign in for each task.

> Because the browser is shared, signing in for one Bot makes the session available to your other Bots.

Websites may expire sessions or require verification again. These are explicit reuse claims within one account's hosted computer; they do not establish import from another browser or portability to another runtime.

For login injection, the documented priority is saved Vault login, connected password manager, then Secure Form:

> Values from Vault and the Secure Form are filled into the page without the Bot seeing them.

Security describes these values as filled “by reference”.

### MCP and runtime

Computer/apps → “Connect an app” (source line breaks normalized):

> A Bot can also add an MCP server that isn't in the catalog, by URL or by a command that runs on its computer; a server started by a command is available to your other Bots too.

Security says remote MCP traffic originates from Cursor infrastructure. These pages do not specify an MCP transport/authentication contract sufficient to establish this project's compatibility.

Security → “Hosting” (source line breaks normalized):

> Grok Bot runs only on Cursor-hosted cloud computers. On-premises deployment, deployment inside your own perimeter, and bring-your-own-image deployment are not supported today.

### Export, migration and recovery limits

Computer/apps describes Update, Recover and Reset operations preserving saved files and logins, with stated limits on recent unsaved changes and installed packages. This is hosted computer recovery, not a documented portable session export.

The 1Password section says:

> The new integration no longer uses a service account

It instructs users of the older integration to reconnect and move old-vault logins to Personal/Private vault:

> The old vault stays in 1Password.

That is a specific integration transition. No portable browser profile, cookie, connector OAuth token, or general credential export/migration procedure was identified in these two pages.

## OpenAI Dot FAQ — blocked

Source: https://help.openai.com/en/articles/20001529-dots-privacy-security-and-safety-faqs

HTTP 403 and `Enable JavaScript and cookies to continue` prevent verifying the article's title or claims. No statement from the user's brief is promoted to fetched fact. Dot identity, native connectors, credential storage, browser login reuse, protocol/runtime/authentication, and export/migration statements dependent on this article remain unverified.

## DSH minimal MCP README — blocked

Source: https://github.com/example-org/private-repo/blob/<commit>/README.md

HTTP 404 with `Page not found · GitHub · GitHub`. The pinned README is inaccessible publicly; whether private or absent is unknown. Its identity, runtime, protocol, authentication, credential handling, browser reuse, and migration statements are all unverified. No authentication or alternate-source guessing was attempted.

## Public DSH dot MCP README

Source: https://github.com/sanshanya/dsh-dot-mcp/blob/a6d4ddac3ca7ec1b0d2baf334f1df5f7d1a81a56/README.md

Heading: “dsh-dot-mcp”. This is a pinned third-party README, not official OpenAI or DeepSeek documentation.

### Identity, protocol and runtime

> One local MCP endpoint onto DeepSeek Harness.

The README describes ChatGPT desktop, Codex or chatgpt.com invoking task/session/goal/approval/result tools, with DSH retaining the runtime. This is a README claim, not a tested Dot connection.

> This tree is v0.9.2 targeting DSH 0.2.1-rc.2.

The client table lists direct stdio, Streamable HTTP at `127.0.0.1:3456/mcp`, and OpenAI Secure MCP Tunnel:

> the tunnel daemon must stay running

> Both speak the identical stateless Streamable HTTP wire.

### Authentication and secret exposure

> The bridge has no token and no auth headers: the listener is loopback-only and DNS-rebinding protected

Under security (source line breaks normalized):

> No authentication. Any local process that can reach 127.0.0.1:<port> can drive every tool the surface serves.

The README instructs users putting it behind a proxy or tunnel to front it with their own auth.

The default core surface has 15 tools:

> dsh_credential_status is full-only and returns plaintext secrets.

> No secret scrubbing. Tool outputs and logs carry caller/agent text verbatim, and dsh_credential_status returns plaintext provider credential values.

This documents potential plaintext provider secret exposure, not browser session reuse or a safe external vault bridge.

The README says bridge settings are written atomically to profile `cordis.patch.yml`; this establishes bridge configuration persistence, not provider credential storage architecture.

> Unofficial community project. Not affiliated with or endorsed by OpenAI or DeepSeek.

No browser profile/cookie import, native browser login reuse, or credential migration workflow was identified. The plaintext credential status tool is distinct from a documented migration workflow.

## Exact public HTTP verification commands and captured status output

The following commands reproduce the command text actually executed. They are historical evidence; no further fetch was performed while saving this document. Output excerpts preserve actual emitted statuses, final URLs, titles and failures. Article body output was filtered by the executed commands; selected quotations above were checked against those results. No complete raw response archive was saved.

### Initial failed attempt

The first attempt used the same seven-URL script shown in the next section, with its opening line `python - <<'PY'` instead of `python3 - <<'PY'`. The shell failed before any script executed. Actual output:

```text
Exit code 127
/bin/bash: line 42: python: command not found
```

### Successful seven-URL verification — exact executed command

```bash
python3 - <<'PY'
import concurrent.futures, urllib.request, urllib.error, re
from html.parser import HTMLParser
urls = [
'https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse',
'https://www.meta.com/help/artificial-intelligence/1687253048996149/',
'https://docs.x.ai/grok-bot/security',
'https://docs.x.ai/grok-bot/computer-and-apps',
'https://help.openai.com/en/articles/20001529-dots-privacy-security-and-safety-faqs',
'https://github.com/example-org/private-repo/blob/<commit>/README.md',
'https://github.com/sanshanya/dsh-dot-mcp/blob/a6d4ddac3ca7ec1b0d2baf334f1df5f7d1a81a56/README.md']
class Text(HTMLParser):
 def __init__(self): super().__init__(); self.skip=0; self.items=[]
 def handle_starttag(self,t,a):
  if t in ('script','style'): self.skip+=1
  if t in ('p','h1','h2','h3','h4','li','div','br'): self.items.append('\n')
 def handle_endtag(self,t):
  if t in ('script','style') and self.skip: self.skip-=1
  if t in ('p','h1','h2','h3','h4','li','div'): self.items.append('\n')
 def handle_data(self,d):
  if not self.skip: self.items.append(d)
def fetch(url):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 try:
  with opener.open(urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=40) as res:
   body=res.read().decode('utf-8','replace'); status=res.status; final=res.url
 except urllib.error.HTTPError as err:
  body=err.read().decode('utf-8','replace'); status=err.code; final=err.url
 except Exception as err: return url+'\nFETCH ERROR '+repr(err)
 p=Text(); p.feed(body)
 text='\n'.join(re.sub(r'\s+',' ',s).strip() for s in ''.join(p.items).splitlines() if s.strip())
 title=re.search(r'<title[^>]*>(.*?)</title>',body,re.I|re.S)
 lines=[url, f'HTTP {status}; FINAL {final}; TITLE '+(title.group(1) if title else '(none)')]
 if status !=200: lines.append(text[:1000])
 else:
  pat=re.compile(r'credent|token|sign.?in|log.?in|OAuth|browser|authd|Secure|Sentinel|SAML|SCIM|export|migrat|Streamable|cordis|identity|Cursor|protocol|nspawn|DevTools|download|vault|tunnel|loopback|DeepSeek|stateless',re.I)
  matches=[s for s in text.splitlines() if pat.search(s)]
  lines.extend(matches[:95])
 return '\n'.join(lines)
with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
 for result in pool.map(fetch,urls): print(result+'\n\n')
PY
```

Actual exit code: `0`. Status/title output lines (intervening article excerpts omitted):

```text
https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse
HTTP 200; FINAL https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse; TITLE How We Built Safety Into Muse | Meta AI Research

https://www.meta.com/help/artificial-intelligence/1687253048996149/
HTTP 200; FINAL https://www.meta.com/help/superintelligence/1687253048996149/; TITLE How Muse works with Connectors | Meta Help Center | Meta

https://docs.x.ai/grok-bot/security
HTTP 200; FINAL https://docs.x.ai/grok-bot/security; TITLE Grok Bot security | SpaceXSI Docs

https://docs.x.ai/grok-bot/computer-and-apps
HTTP 200; FINAL https://docs.x.ai/grok-bot/computer-and-apps; TITLE Use the computer and apps | SpaceXSI Docs

https://help.openai.com/en/articles/20001529-dots-privacy-security-and-safety-faqs
HTTP 403; FINAL https://help.openai.com/en/articles/20001529-dots-privacy-security-and-safety-faqs; TITLE (none)
Enable JavaScript and cookies to continue

https://github.com/example-org/private-repo/blob/<commit>/README.md
HTTP 404; FINAL https://github.com/example-org/private-repo/blob/<commit>/README.md; TITLE Page not found · GitHub · GitHub
Page not found · GitHub · GitHub

https://github.com/sanshanya/dsh-dot-mcp/blob/a6d4ddac3ca7ec1b0d2baf334f1df5f7d1a81a56/README.md
HTTP 200; FINAL https://github.com/sanshanya/dsh-dot-mcp/blob/a6d4ddac3ca7ec1b0d2baf334f1df5f7d1a81a56/README.md; TITLE dsh-dot-mcp/README.md at a6d4ddac3ca7ec1b0d2baf334f1df5f7d1a81a56 · sanshanya/dsh-dot-mcp · GitHub
```

### Focused quotation follow-up — exact executed command

This second batch fetched only the five accessible pages and printed matching lines with neighboring context. It did not print status/header metadata. It exited `0`; no fetch exceptions were printed.

```bash
python3 - <<'PY'
import concurrent.futures, urllib.request, re
from html.parser import HTMLParser
class Text(HTMLParser):
 def __init__(self): super().__init__(); self.skip=0; self.out=[]
 def handle_starttag(self,t,a):
  if t in ('script','style'): self.skip+=1
  if t in ('p','h1','h2','h3','h4','li','br'): self.out.append('\n')
 def handle_endtag(self,t):
  if t in ('script','style') and self.skip:self.skip-=1
  if t in ('p','h1','h2','h3','h4','li'):self.out.append('\n')
 def handle_data(self,d):
  if not self.skip:self.out.append(d)
jobs=[
('https://www.meta.com/help/artificial-intelligence/1687253048996149/',r'Meta Connectors|Custom|Accounts Center|disconnect|authorization'),
('https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse',r'Connectors|Unix domain|download these|This extends|OAuth'),
('https://docs.x.ai/grok-bot/security',r'A Bot has|Bots act|Application sessions|Connector tokens|Credentials stay|durable disk|Data retention|Hosting|Grok Bot runs'),
('https://docs.x.ai/grok-bot/computer-and-apps',r'computer is assigned|Browser cookies|Sign in once|App logins|OAuth tokens|server started|MCP server|old vault|service account'),
('https://github.com/sanshanya/dsh-dot-mcp/blob/a6d4ddac3ca7ec1b0d2baf334f1df5f7d1a81a56/README.md',r'One local|This tree|Both speak|Environment|credential_status|cordis.patch|Unofficial|127.0.0.1:<port>|default')]
def work(job):
 url,pat=job
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=40) as res:body=res.read().decode()
 p=Text();p.feed(body);lines=[re.sub(r'\s+',' ',s).strip() for s in ''.join(p.out).splitlines() if s.strip()]
 picks=set()
 for i,line in enumerate(lines):
  if re.search(pat,line,re.I):picks.update(range(max(0,i-1),min(len(lines),i+3)))
 return url+'\n'+'\n'.join(lines[i] for i in sorted(picks))
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
 for result in pool.map(work,jobs): print(result+'\n\n')
PY
```

## Evidence boundary

- Public source accessibility is verified only for the fetches recorded here.
- Documentation describes credential storage and reuse behavior; no runtime behavior was exercised.
- Grok's explicit same-account shared browser state does not establish portability to this project.
- Muse's stored-password injection and VM-local credential claims do not establish this project's connector compatibility or a credential extraction mechanism.
- The public third-party DSH README's MCP and secret exposure claims are not an endorsement, compatibility result, or executed test.
- The inaccessible OpenAI FAQ and DSH minimal README remain blocked; there is no inferred substitute evidence.
- Muse, Grok and Dot product-level tests remain blocked because the relevant cloud accounts are absent.

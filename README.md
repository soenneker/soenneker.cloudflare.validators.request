[![](https://img.shields.io/nuget/v/soenneker.cloudflare.validators.request.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.cloudflare.validators.request/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.cloudflare.validators.request/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.cloudflare.validators.request/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.cloudflare.validators.request.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.cloudflare.validators.request/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.cloudflare.validators.request/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.cloudflare.validators.request/actions/workflows/codeql.yml)

# Soenneker.Cloudflare.Validators.Request

Validates an ASP.NET Core request's TLS client certificate against Cloudflare's Authenticated Origin Pull CA.

## Installation

```bash
dotnet add package Soenneker.Cloudflare.Validators.Request
```

## Registration

```csharp
using Soenneker.Cloudflare.Validators.Request.Registrars;

services.AddCloudflareRequestValidatorAsSingleton();
```

The package supplies the Cloudflare Authenticated Origin Pull CA certificate as a build resource. Set `Cloudflare:RequestValidatorLog` to `true` only when debug logging for missing or invalid certificates is useful.

## Usage

```csharp
using Soenneker.Cloudflare.Validators.Request.Abstract;

bool fromCloudflare = await validator.IsFromCloudflare(
    httpContext,
    httpContext.RequestAborted);

if (!fromCloudflare)
{
    httpContext.Response.StatusCode = StatusCodes.Status403Forbidden;
    return;
}
```

`IsFromCloudflare` requires a client certificate on `HttpContext.Connection.ClientCertificate`. It builds a custom-trust chain to the packaged Cloudflare CA, requires the client-authentication extended key usage, disables certificate downloads, and performs normal certificate validity checks.

## Required origin setup

This validator is meaningful only when all of the following are true:

- Authenticated Origin Pulls is enabled for the Cloudflare zone.
- The public origin accepts traffic only through Cloudflare or otherwise requires a valid client certificate.
- The TLS endpoint serving ASP.NET Core requests requests and forwards the actual client certificate.

If TLS terminates at a load balancer or reverse proxy, configure certificate forwarding only across a trusted internal boundary. A public request header is not proof of a client certificate and must not be copied into `ClientCertificate` without authenticating the proxy that supplied it.

`Validate(string)` is a lower-level fingerprint comparison. It compares the supplied hexadecimal SHA-256 value with the packaged **CA certificate**; it does not validate a request or leaf certificate chain.

This package verifies Cloudflare's shared Authenticated Origin Pull CA, not a zone-specific origin-pull certificate. For enforcement in MVC applications, `Soenneker.Cloudflare.Attributes.Require` provides an authorization filter built on this validator.

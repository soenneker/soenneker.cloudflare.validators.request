using Microsoft.AspNetCore.Http;
using Soenneker.Validators.Validator.Abstract;
using System;
using System.Diagnostics.Contracts;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Cloudflare.Validators.Request.Abstract;

/// <summary>
/// Validates ASP.NET Core client certificates against Cloudflare's Authenticated Origin Pull CA.
/// </summary>
public interface ICloudflareRequestValidator : IValidator, IDisposable, IAsyncDisposable
{
    /// <summary>
    /// Validates the request's TLS client certificate chain against the packaged Cloudflare Authenticated Origin Pull CA.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task containing the result of the operation.</returns>
    [Pure]
    ValueTask<bool> IsFromCloudflare(HttpContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Compares a SHA-256 certificate fingerprint with the packaged Cloudflare Authenticated Origin Pull CA certificate.
    /// </summary>
    /// <param name="thumbprint">The hexadecimal SHA-256 fingerprint to compare.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task containing the result of the operation.</returns>
    [Pure]
    ValueTask<bool> Validate(string thumbprint, CancellationToken cancellationToken = default);
}

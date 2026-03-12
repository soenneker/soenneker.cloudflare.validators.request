using Microsoft.AspNetCore.Http;
using Soenneker.Validators.Validator.Abstract;
using System;
using System.Diagnostics.Contracts;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Cloudflare.Validators.Request.Abstract;

/// <summary>
/// A validation module checking if a particular request has a Cloudflare origin certificate
/// </summary>
public interface ICloudflareRequestValidator : IValidator, IDisposable, IAsyncDisposable
{
    [Pure]
    ValueTask<bool> IsFromCloudflare(HttpContext context, CancellationToken cancellationToken = default);

    [Pure]
    ValueTask<bool> Validate(string thumbprint, CancellationToken cancellationToken = default);
}
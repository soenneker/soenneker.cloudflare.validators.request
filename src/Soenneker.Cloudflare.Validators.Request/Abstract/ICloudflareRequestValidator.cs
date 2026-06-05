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
    /// <summary>
    /// Executes the is from cloudflare operation.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task containing the result of the operation.</returns>
    [Pure]
    ValueTask<bool> IsFromCloudflare(HttpContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes the validate operation.
    /// </summary>
    /// <param name="thumbprint">The thumbprint.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task containing the result of the operation.</returns>
    [Pure]
    ValueTask<bool> Validate(string thumbprint, CancellationToken cancellationToken = default);
}
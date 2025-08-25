using Soenneker.Validators.Validator.Abstract;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Cloudflare.Validators.Request.Abstract;

/// <summary>
/// A validation module checking if a particular request has a Cloudflare origin certificate
/// </summary>
public interface ICloudflareRequestValidator : IValidator, IDisposable, IAsyncDisposable
{
    ValueTask<bool> Validate(string thumbprint, CancellationToken cancellationToken = default);
}

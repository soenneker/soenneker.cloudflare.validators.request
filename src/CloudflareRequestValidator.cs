using Microsoft.Extensions.Logging;
using Soenneker.Cloudflare.Validators.Request.Abstract;
using Soenneker.Extensions.ValueTask;
using Soenneker.Utils.AsyncSingleton;
using Soenneker.Utils.File.Abstract;
using Soenneker.Validators.Validator;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Extensions.String;

namespace Soenneker.Cloudflare.Validators.Request;

/// <inheritdoc cref="ICloudflareRequestValidator"/>
public sealed class CloudflareRequestValidator : Validator, ICloudflareRequestValidator
{
    private readonly AsyncSingleton<HashSet<string>> _thumbprintsSet;

    public CloudflareRequestValidator(ILogger<CloudflareRequestValidator> logger, IFileUtil fileUtil) : base(logger)
    {
        _thumbprintsSet = new AsyncSingleton<HashSet<string>>(async (token, _) =>
        {
            return await fileUtil.ReadToHashSet(Path.Combine("Resources", "cloudflareorigincerts.txt"), StringComparer.OrdinalIgnoreCase, cancellationToken: token).NoSync();
        });
    }

    public async ValueTask<bool> Validate(string thumbprint, CancellationToken cancellationToken = default)
    {
        if (thumbprint.IsNullOrEmpty())
            return false;

        if ((await _thumbprintsSet.Get(cancellationToken)).Contains(thumbprint))
            return true;

        return false;
    }

    public ValueTask DisposeAsync()
    {
        return _thumbprintsSet.DisposeAsync();
    }

    public void Dispose()
    {
        _thumbprintsSet.Dispose();
    }
}
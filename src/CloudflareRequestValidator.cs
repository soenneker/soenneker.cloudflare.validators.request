using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Soenneker.Cloudflare.Validators.Request.Abstract;
using Soenneker.Extensions.String;
using Soenneker.Extensions.ValueTask;
using Soenneker.Utils.AsyncSingleton;
using Soenneker.Utils.File.Abstract;
using Soenneker.Utils.Paths.Resources;
using Soenneker.Validators.Validator;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Extensions.Spans.Readonly.Bytes;

namespace Soenneker.Cloudflare.Validators.Request;

/// <inheritdoc cref="ICloudflareRequestValidator"/>
public sealed class CloudflareRequestValidator : Validator, ICloudflareRequestValidator
{
    private readonly AsyncSingleton<HashSet<string>> _thumbprintsSet;

    private readonly bool _log;

    public CloudflareRequestValidator(ILogger<CloudflareRequestValidator> logger, IFileUtil fileUtil, IConfiguration configuration) : base(logger)
    {
        _log = configuration.GetValue<bool>("Cloudflare:RequestValidatorLog");

        _thumbprintsSet = new AsyncSingleton<HashSet<string>>(async (token) =>
        {
            string path = await ResourcesPathUtil.GetResourceFilePath("cloudflareorigincerts.txt").NoSync();

            return await fileUtil.ReadToHashSet(path, StringComparer.OrdinalIgnoreCase, cancellationToken: token).NoSync();
        });
    }

    public async ValueTask<bool> IsFromCloudflare(HttpContext context, CancellationToken cancellationToken = default)
    {
        X509Certificate2? cert = context.Connection.ClientCertificate;

        if (cert is null)
        {
            if (_log)
                Logger.LogDebug("No client certificate present");

            return false;
        }

        ReadOnlySpan<byte> data = cert.RawData;

        return await Validate(data.ToSha256Hex(), cancellationToken).NoSync();
    }

    public async ValueTask<bool> Validate(string thumbprint, CancellationToken cancellationToken = default)
    {
        if (thumbprint.IsNullOrWhiteSpace())
        {
            if (_log)
                Logger.LogDebug("Thumbprint was null or whitespace");

            return false;
        }

        if ((await _thumbprintsSet.Get(cancellationToken).NoSync()).Contains(thumbprint))
        {
            if (_log)
                Logger.LogDebug("Incoming certificate thumbprint ({incoming}) is not a current Cloudflare certificate thumbprint", thumbprint);

            return true;
        }

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
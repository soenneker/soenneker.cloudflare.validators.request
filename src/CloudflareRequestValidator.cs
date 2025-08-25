using Microsoft.Extensions.Logging;
using Soenneker.Cloudflare.Validators.Request.Abstract;
using Soenneker.Extensions.String;
using Soenneker.Extensions.ValueTask;
using Soenneker.Utils.AsyncSingleton;
using Soenneker.Utils.File.Abstract;
using Soenneker.Validators.Validator;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Soenneker.Cloudflare.Validators.Request;

/// <inheritdoc cref="ICloudflareRequestValidator"/>
public sealed class CloudflareRequestValidator : Validator, ICloudflareRequestValidator
{
    private readonly AsyncSingleton<HashSet<string>> _thumbprintsSet;

    private readonly bool _log;

    public CloudflareRequestValidator(ILogger<CloudflareRequestValidator> logger, IFileUtil fileUtil, IConfiguration configuration) : base(logger)
    {
        _log = configuration.GetValue<bool>("CloudflareRequestValidator:Log");

        _thumbprintsSet = new AsyncSingleton<HashSet<string>>(async (token, _) =>
        {
            return await fileUtil.ReadToHashSet(Path.Combine("Resources", "cloudflareorigincerts.txt"), StringComparer.OrdinalIgnoreCase,
                                     cancellationToken: token)
                                 .NoSync();
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

        Span<byte> sha256 = stackalloc byte[32];

        using (var hasher = SHA256.Create())
        {
            if (!hasher.TryComputeHash(cert.RawData, sha256, out _))
            {
                if (_log)
                    Logger.LogDebug("Could not compute hash for certificate's raw data");

                return false;
            }
        }

        Span<char> hex = stackalloc char[64];

        for (var i = 0; i < sha256.Length; i++)
        {
            byte b = sha256[i];
            int hi = b >> 4, lo = b & 0xF;
            hex[i * 2] = (char) (hi < 10 ? '0' + hi : 'A' + (hi - 10));
            hex[i * 2 + 1] = (char) (lo < 10 ? '0' + lo : 'A' + (lo - 10));
        }

        var thumbHex = new string(hex); // e.g., “AB12…”

        return await Validate(thumbHex, cancellationToken).NoSync();
    }

    public async ValueTask<bool> Validate(string thumbprint, CancellationToken cancellationToken = default)
    {
        if (thumbprint.IsNullOrWhiteSpace())
        {
            if (_log)
                Logger.LogDebug("Thumbprint was null or whitespace");

            return false;
        }

        if ((await _thumbprintsSet.Get(cancellationToken)).Contains(thumbprint))
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
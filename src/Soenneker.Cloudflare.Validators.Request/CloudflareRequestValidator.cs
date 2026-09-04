using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Soenneker.Cloudflare.Validators.Request.Abstract;
using Soenneker.Extensions.String;
using Soenneker.Extensions.ValueTask;
using Soenneker.Hashing.Sha256;
using Soenneker.Utils.AsyncSingleton;
using Soenneker.Utils.File.Abstract;
using Soenneker.Utils.Paths.Resources.Abstract;
using Soenneker.Validators.Validator;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Cloudflare.Validators.Request;

/// <inheritdoc cref="ICloudflareRequestValidator" />
public sealed class CloudflareRequestValidator : Validator, ICloudflareRequestValidator
{
    private static readonly Sha256HashingUtil _sha256 = new();

    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private readonly AsyncSingleton<byte[]> _caCertificate;
    private readonly IFileUtil _fileUtil;
    private readonly IResourcesPathUtil _resourcesPathUtil;

    private readonly bool _log;

    public CloudflareRequestValidator(ILogger<CloudflareRequestValidator> logger, IFileUtil fileUtil, IResourcesPathUtil resourcesPathUtil, IConfiguration configuration) : base(logger)
    {
        _fileUtil = fileUtil;
        _resourcesPathUtil = resourcesPathUtil;
        _log = configuration.GetValue<bool>("Cloudflare:RequestValidatorLog");

        _caCertificate = new AsyncSingleton<byte[]>(LoadCaCertificate);
    }

    private async ValueTask<byte[]> LoadCaCertificate(CancellationToken token)
    {
        string path = await _resourcesPathUtil.GetResourceFilePath("cloudflareorigincerts.pem", token).NoSync();
        string? pem = await _fileUtil.TryRead(path, cancellationToken: token).NoSync();

        if (pem.IsNullOrWhiteSpace())
            throw new InvalidOperationException($"Cloudflare AOP CA certificate was not found at {path}");

        using X509Certificate2 certificate = X509Certificate2.CreateFromPem(pem);
        return certificate.RawData;
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

        byte[] caRawData = await _caCertificate.Get(cancellationToken).NoSync();
        using X509Certificate2 caCertificate = X509CertificateLoader.LoadCertificate(caRawData);
        bool valid = ValidateCertificateChain(cert, caCertificate);

        if (_log)
            Logger.LogDebug("Cloudflare client certificate chain validation result: {valid}", valid);

        return valid;
    }

    internal static bool ValidateCertificateChain(X509Certificate2 certificate, X509Certificate2 caCertificate)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(caCertificate);
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuthenticationOid));
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        return chain.Build(certificate) && chain.ChainElements.Count > 1;
    }

    public async ValueTask<bool> Validate(string thumbprint, CancellationToken cancellationToken = default)
    {
        if (thumbprint.IsNullOrWhiteSpace())
        {
            if (_log)
                Logger.LogDebug("Thumbprint was null or whitespace");

            return false;
        }

        byte[] caRawData = await _caCertificate.Get(cancellationToken).NoSync();
        string expected = Convert.ToHexString(_sha256.Hash(caRawData));
        return expected.Equals(thumbprint, StringComparison.OrdinalIgnoreCase);
    }

    public ValueTask DisposeAsync()
    {
        return _caCertificate.DisposeAsync();
    }

    public void Dispose()
    {
        _caCertificate.Dispose();
    }
}

using Microsoft.AspNetCore.Http;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Soenneker.Cloudflare.Validators.Request.Abstract;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.Cloudflare.Validators.Request.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class CloudflareRequestValidatorTests : HostedUnitTest
{
    private readonly ICloudflareRequestValidator _validator;

    public CloudflareRequestValidatorTests(Host host) : base(host)
    {
        _validator = Resolve<ICloudflareRequestValidator>(true);
    }

    [Test]
    public void Default()
    {

    }

    [Test]
    public async ValueTask Validate_should_be_true(CancellationToken cancellationToken)
    {
        bool result = await _validator.Validate("9A1AC2B4BE15F9F27EEE20A734CBA4E9898F61001B3BD7C84B69B56A3E25A2B9", cancellationToken);

        result.Should()
              .BeTrue();
    }

    [Test]
    public void ValidateCertificateChain_should_accept_client_certificate_signed_by_CA()
    {
        using RSA caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=Test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using X509Certificate2 ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));

        using RSA leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=origin-pull.cloudflare.net", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var usages = new OidCollection { new("1.3.6.1.5.5.7.3.2") };
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        using X509Certificate2 leaf = leafRequest.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1), serial);

        CloudflareRequestValidator.ValidateCertificateChain(leaf, ca)
                                  .Should()
                                  .BeTrue();
    }

    [Test]
    public async ValueTask IsFromCloudflare_should_reject_CA_as_client_certificate(CancellationToken cancellationToken)
    {
        const string pem = """
                           -----BEGIN CERTIFICATE-----
                           MIIGCjCCA/KgAwIBAgIIV5G6lVbCLmEwDQYJKoZIhvcNAQENBQAwgZAxCzAJBgNV
                           BAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMRQwEgYDVQQLEwtPcmln
                           aW4gUHVsbDEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzETMBEGA1UECBMKQ2FsaWZv
                           cm5pYTEjMCEGA1UEAxMab3JpZ2luLXB1bGwuY2xvdWRmbGFyZS5uZXQwHhcNMTkx
                           MDEwMTg0NTAwWhcNMjkxMTAxMTcwMDAwWjCBkDELMAkGA1UEBhMCVVMxGTAXBgNV
                           BAoTEENsb3VkRmxhcmUsIEluYy4xFDASBgNVBAsTC09yaWdpbiBQdWxsMRYwFAYD
                           VQQHEw1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlhMSMwIQYDVQQD
                           ExpvcmlnaW4tcHVsbC5jbG91ZGZsYXJlLm5ldDCCAiIwDQYJKoZIhvcNAQEBBQAD
                           ggIPADCCAgoCggIBAN2y2zojYfl0bKfhp0AJBFeV+jQqbCw3sHmvEPwLmqDLqynI
                           42tZXR5y914ZB9ZrwbL/K5O46exd/LujJnV2b3dzcx5rtiQzso0xzljqbnbQT20e
                           ihx/WrF4OkZKydZzsdaJsWAPuplDH5P7J82q3re88jQdgE5hqjqFZ3clCG7lxoBw
                           hLaazm3NJJlUfzdk97ouRvnFGAuXd5cQVx8jYOOeU60sWqmMe4QHdOvpqB91bJoY
                           QSKVFjUgHeTpN8tNpKJfb9LIn3pun3bC9NKNHtRKMNX3Kl/sAPq7q/AlndvA2Kw3
                           Dkum2mHQUGdzVHqcOgea9BGjLK2h7SuX93zTWL02u799dr6Xkrad/WShHchfjjRn
                           aL35niJUDr02YJtPgxWObsrfOU63B8juLUphW/4BOjjJyAG5l9j1//aUGEi/sEe5
                           lqVv0P78QrxoxR+MMXiJwQab5FB8TG/ac6mRHgF9CmkX90uaRh+OC07XjTdfSKGR
                           PpM9hB2ZhLol/nf8qmoLdoD5HvODZuKu2+muKeVHXgw2/A6wM7OwrinxZiyBk5Hh
                           CvaADH7PZpU6z/zv5NU5HSvXiKtCzFuDu4/Zfi34RfHXeCUfHAb4KfNRXJwMsxUa
                           +4ZpSAX2G6RnGU5meuXpU5/V+DQJp/e69XyyY6RXDoMywaEFlIlXBqjRRA2pAgMB
                           AAGjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1Ud
                           DgQWBBRDWUsraYuA4REzalfNVzjann3F6zAfBgNVHSMEGDAWgBRDWUsraYuA4REz
                           alfNVzjann3F6zANBgkqhkiG9w0BAQ0FAAOCAgEAkQ+T9nqcSlAuW/90DeYmQOW1
                           QhqOor5psBEGvxbNGV2hdLJY8h6QUq48BCevcMChg/L1CkznBNI40i3/6heDn3IS
                           zVEwXKf34pPFCACWVMZxbQjkNRTiH8iRur9EsaNQ5oXCPJkhwg2+IFyoPAAYURoX
                           VcI9SCDUa45clmYHJ/XYwV1icGVI8/9b2JUqklnOTa5tugwIUi5sTfipNcJXHhgz
                           6BKYDl0/UP0lLKbsUETXeTGDiDpxZYIgbcFrRDDkHC6BSvdWVEiH5b9mH2BON60z
                           0O0j8EEKTwi9jnafVtZQXP/D8yoVowdFDjXcKkOPF/1gIh9qrFR6GdoPVgB3SkLc
                           5ulBqZaCHm563jsvWb/kXJnlFxW+1bsO9BDD6DweBcGdNurgmH625wBXksSdD7y/
                           fakk8DagjbjKShYlPEFOAqEcliwjF45eabL0t27MJV61O/jHzHL3dknXeE4BDa2j
                           bA+JbyJeUMtU7KMsxvx82RmhqBEJJDBCJ3scVptvhDMRrtqDBW5JShxoAOcpFQGm
                           iYWicn46nPDjgTU0bX1ZPpTpryXbvciVL5RkVBuyX2ntcOLDPlZWgxZCBp96x07F
                           AnOzKgZk4RzZPNAxCXERVxajn/FLcOhglVAKo5H0ac+AitlQ0ip55D2/mf8o72tM
                           fVQ6VpyjEXdiIXWUq/o=
                           -----END CERTIFICATE-----
                           """;

        using X509Certificate2 certificate = X509Certificate2.CreateFromPem(pem);
        var context = new DefaultHttpContext();
        context.Connection.ClientCertificate = certificate;

        bool result = await _validator.IsFromCloudflare(context, cancellationToken);

        result.Should()
              .BeFalse();
    }
}

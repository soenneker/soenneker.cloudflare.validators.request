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
        bool result = await _validator.Validate("1F5BA8DCF83E6453DD75C47780906710901AD641", cancellationToken);

        result.Should()
              .BeTrue();
    }
}

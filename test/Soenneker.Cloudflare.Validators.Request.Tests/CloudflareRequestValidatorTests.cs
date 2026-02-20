using System.Threading.Tasks;
using AwesomeAssertions;
using Soenneker.Cloudflare.Validators.Request.Abstract;
using Soenneker.Tests.FixturedUnit;
using Xunit;

namespace Soenneker.Cloudflare.Validators.Request.Tests;

[Collection("Collection")]
public sealed class CloudflareRequestValidatorTests : FixturedUnitTest
{
    private readonly ICloudflareRequestValidator _validator;

    public CloudflareRequestValidatorTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
        _validator = Resolve<ICloudflareRequestValidator>(true);
    }

    [Fact]
    public void Default()
    {

    }

    [Fact]
    public async ValueTask Validate_should_be_true()
    {
        bool result = await _validator.Validate("1F5BA8DCF83E6453DD75C47780906710901AD641", CancellationToken);

        result.Should()
              .BeTrue();
    }
}

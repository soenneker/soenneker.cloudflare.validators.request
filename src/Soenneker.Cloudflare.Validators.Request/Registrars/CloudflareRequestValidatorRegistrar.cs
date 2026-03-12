using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Cloudflare.Validators.Request.Abstract;
using Soenneker.Utils.File.Registrars;
using Soenneker.Utils.Paths.Resources.Registrars;

namespace Soenneker.Cloudflare.Validators.Request.Registrars;

/// <summary>
/// A validation module checking if a particular request has a Cloudflare origin certificate
/// </summary>
public static class CloudflareRequestValidatorRegistrar
{
    /// <summary>
    /// Adds <see cref="ICloudflareRequestValidator"/> as a singleton service. <para/>
    /// </summary>
    public static IServiceCollection AddCloudflareRequestValidatorAsSingleton(this IServiceCollection services)
    {
        services.AddResourcesPathUtilAsSingleton().AddFileUtilAsSingleton().TryAddSingleton<ICloudflareRequestValidator, CloudflareRequestValidator>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="ICloudflareRequestValidator"/> as a scoped service. <para/>
    /// </summary>
    public static IServiceCollection AddCloudflareRequestValidatorAsScoped(this IServiceCollection services)
    {
        services.AddResourcesPathUtilAsScoped().AddFileUtilAsScoped().TryAddScoped<ICloudflareRequestValidator, CloudflareRequestValidator>();

        return services;
    }
}
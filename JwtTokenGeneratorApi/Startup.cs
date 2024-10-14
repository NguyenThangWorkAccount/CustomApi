using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        // Add services to the container.
        services.AddControllers(); // Add MVC controllers
        // Register other services needed by your application here
    }

    public void Configure(IApplicationBuilder app)
    {
        // Configure the HTTP request pipeline.
        app.UseRouting();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers(); // Map attribute routed controllers
        });
    }
}

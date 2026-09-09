using System.Text.Json.Serialization;
using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.Infrastructure.AutoMapper;
using Cve.Infrastructure.Extensions;
using Cve.Infrastructure.Helpers;
using Cve.Infrastructure.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Infrastructure.Configuration;
using Cve.Net.Search.Infrastructure.Services.Cve;
using Cve.Net.Search.Web.Infrastructure.Hangfire;
using Hangfire;
using Hangfire.MemoryStorage;
using Microsoft.OpenApi.Models;

namespace Cve.Net.Search.Web;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.

        builder.Services.AddControllers();
        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("cve", new OpenApiInfo { Title = "CVE Search API" });

            options.IncludeXmlComments(
                Path.Combine(AppContext.BaseDirectory, "Cve.Net.Search.Web.xml"));
            options.IncludeXmlComments(
               Path.Combine(AppContext.BaseDirectory, "Cve.Net.Search.Domain.Common.xml"));
            options.IncludeXmlComments(
                Path.Combine(AppContext.BaseDirectory, "Cve.Net.Search.Domain.ViewModels.xml"));
        });

        builder.Services.AddMvc().AddJsonOptions(options =>
        {
            options.JsonSerializerOptions.WriteIndented = true;
            options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        }).AddNewtonsoftJson();

        builder.Services.AddMongoDb(builder.Configuration);

        builder.Services.AddHangfire(config =>
        {
            config.UseMemoryStorage();
        });

        builder.Services.AddHangfireServer(options =>
        {
            options.ServerName = "ASP.NET Core In-Process";
            options.WorkerCount = Environment.ProcessorCount * 2;
        });

        builder.Services.Configure<VulnerabilitiesUrls>(builder.Configuration.GetSection("Vulnerabilities"));
        builder.Services.AddHttpClient();


        builder.Services.AddSingleton<ICweMongoService, CweMongoService>();
        builder.Services.AddSingleton<ICveMongoService, CveMongoService>();
        builder.Services.AddSingleton<ICapecMongoService, CapecMongoService>();
        builder.Services.AddSingleton<IVendorMongoService, VendorMongoService>();
        builder.Services.AddTransient<IVulnerabilitiesJsonHelper, VulnerabilitiesJsonHelper>();
        builder.Services.AddAutoMapper(typeof(VulnerabilitiesProfile));
        builder.Services.AddHealthChecks();

        var app = builder.Build();

        app.UseSwagger();

        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint("/swagger/cve/swagger.json", "CVE Search API");
        });

        app.UseHttpsRedirection();
        app.UseAuthorization();

        app.MapHealthChecks("/health");

        var dashboardUserConfig =
            app.Configuration.GetSection("HangfireDashboarAuth").Get<HangfireDashboardAuth>();

        var hangfireAuth = new BasicAuthAuthorizationFilter(new BasicAuthAuthorizationFilterOptions
        {
            LoginCaseSensitive = true,
            Users = new[]
            {
                new BasicAuthAuthorizationUser
                {
                    Login = dashboardUserConfig.UserName,
                    PasswordClear = dashboardUserConfig.Password
                }
            }
        });

        var options = new DashboardOptions
        {
            Authorization = new[]
            {
                hangfireAuth
            }
        };

        app.UseHangfireDashboard("/hangfire", options);

        BackgroundJob.Enqueue<IVulnerabilitiesJsonHelper>(job => job.PopulateDatabaseInitially(CancellationToken.None));

        RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(nameof(IVulnerabilitiesJsonHelper.PopulateDatabaseInitially),
            job => job.PopulateDatabaseInitially(CancellationToken.None), Cron.Never);

        RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(nameof(IVulnerabilitiesJsonHelper.LoadNewAndModifiedPerHourCves),
            job => job.LoadNewAndModifiedPerHourCves(CancellationToken.None), "0 * * * *");

        RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(nameof(IVulnerabilitiesJsonHelper.LoadCurrentYearCves),
            job => job.LoadCurrentYearCves(CancellationToken.None), Cron.Daily);

        RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(nameof(IVulnerabilitiesJsonHelper.LoadCwesAndCapecs),
            job => job.LoadCwesAndCapecs(CancellationToken.None), Cron.Daily);

        RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(nameof(IVulnerabilitiesJsonHelper.LoadCurrentDayCves),
            job => job.LoadCurrentDayCves(CancellationToken.None), "30 */3 * * *");

        app.MapControllers();

        app.Run();
    }
}

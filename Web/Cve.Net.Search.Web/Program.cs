using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json.Serialization;
using Cve.Infrastructure.Extensions;
using Hangfire;
using Hangfire.MemoryStorage;
using System;
using Cve.Application.Helpers;
using Cve.Infrastructure.Helpers;
using Cve.Application.Services;
using Cve.Infrastructure.Services;
using Cve.Infrastructure.AutoMapper;
using Microsoft.OpenApi.Models;
using System.IO;
using Cve.Net.Search.Infrastructure.Configuration;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Infrastructure.Services.Cve;
using Microsoft.Extensions.Configuration;
using Hangfire.Dashboard;
using Microsoft.Extensions.Hosting;
using Cve.Net.Search.Web.Infrastructure.Hangfire;

namespace Cve.Net.Search.Web
{
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

            builder.Services.Configure<KestrelServerOptions>(options =>
            {
                options.AllowSynchronousIO = true;
            });

            builder.Services.Configure<IISServerOptions>(options =>
            {
                options.AllowSynchronousIO = true;
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
            builder.Services.AddSingleton<ICveModifiedMongoService, CveModifiedMongoService>();
            builder.Services.AddSingleton<ICapecMongoService, CapecMongoService>();
            builder.Services.AddSingleton<IVendorMongoService, VendorMongoService>();
            builder.Services.AddTransient<IVulnerabilitiesJsonHelper, VulnerabilitiesJsonHelper>();
            builder.Services.AddAutoMapper(typeof(VulnerabilitiesProfile));

            var app = builder.Build();

            app.UseSwagger();

            app.UseSwaggerUI(options =>
            {
                options.SwaggerEndpoint("/swagger/cve/swagger.json", "CVE Search API");
            });

            app.UseHttpsRedirection();
            app.UseAuthorization();

            var dashboardUserConfig =
                app.Configuration.GetSection("HangfireDashboarAuth").Get<HangfireDashboardAuth>();

            var hangfireAuth = new BasicAuthAuthorizationFilter(new BasicAuthAuthorizationFilterOptions
            {
                RequireSsl = false,
                SslRedirect = false,
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
                Authorization = new []
                {
                    hangfireAuth
                }
            };

            app.UseHangfireDashboard("/hangfire", options);

            BackgroundJob.Enqueue<IVulnerabilitiesJsonHelper>(job => job.PopulateDatabaseInitially());

            RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(job => job.PopulateDatabaseInitially(), Cron.Never);

            RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(job => job.LoadNewAndModifiedCves(), "0 * * * *");

            app.MapControllers();

            app.Run();
        }
    }
}
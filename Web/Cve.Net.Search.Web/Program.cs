using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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

            app.UseHangfireDashboard("/hangfire");

            BackgroundJob.Enqueue<IVulnerabilitiesJsonHelper>(job => job.PopulateDatabaseInitially());

            RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(job => job.PopulateDatabaseInitially(), Cron.Never);

            RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(job => job.LoadNewAndModifiedCves(), "0 * * * *");

            app.MapControllers();

            app.Run();
        }
    }
}
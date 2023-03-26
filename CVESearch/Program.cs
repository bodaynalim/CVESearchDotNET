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
using Microsoft.Extensions.Options;
using Cve.Application.Helpers;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Cve.Infrastructure.Helpers;
using Cve.Application.Services;
using Cve.Infrastructure.Services;

namespace CVESearch
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
            builder.Services.AddSwaggerGen();

            

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
            
            builder.Services.AddSingleton<ICweMongoService, CweMongoService>();
            builder.Services.AddSingleton<ICveMongoService, CveMongoService>();
            builder.Services.AddSingleton<ICapecMongoService, CapecMongoService>();
            builder.Services.AddTransient<IVulnerabilitiesJsonHelper, VulnerabilitiesJsonHelper>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseAuthorization();

            app.UseHangfireDashboard("/hangfire");

            BackgroundJob.Enqueue<IVulnerabilitiesJsonHelper>(job => job.PopulateDatabaseInitially());

            RecurringJob.AddOrUpdate<IVulnerabilitiesJsonHelper>(job => job.PopulateDatabaseInitially(), Cron.Never);

            app.MapControllers();

            app.Run();
        }
    }
}
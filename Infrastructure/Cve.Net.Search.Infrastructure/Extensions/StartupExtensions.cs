using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;

namespace Cve.Infrastructure.Extensions
{
    public static class StartupExtensions
    {
        public static MongoClient AddMongoDb(this IServiceCollection services, IConfiguration configuration)
        {
            var client = new MongoClient(configuration.GetConnectionString("Mongo"));

            services.AddSingleton(serviceProvider => client);

            services.AddSingleton(
                serviceProvider =>
                {
                    var db = serviceProvider.GetRequiredService<MongoClient>();

                    return db.GetDatabase(
                        configuration.GetValue<string>("DatabaseName"));
                });

            return client;
        }
    }
}

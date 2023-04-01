using System.Collections.Generic;
using System.Linq;
using Hangfire;
using Hangfire.Storage.Monitoring;

namespace Cve.Infrastructure.Extensions 
{ 
    public sealed class BackgroundJobsModule
    {
        public static Dictionary<string, ProcessingJobDto> GetRunningJobByName(string jobMethodName)
        {
            var api = JobStorage.Current.GetMonitoringApi();

            var processingJob = api.ProcessingJobs(0, int.MaxValue);

            return processingJob?.Where(j => j.Value.Job.Method.Name == jobMethodName)
                .ToDictionary(j => j.Key, j => j.Value);
        }

        public static bool CheckJobIsRunningOrScheduledByName(string jobMethodName)
        {
            var api = JobStorage.Current.GetMonitoringApi();

            var processingJob = api.ProcessingJobs(0, int.MaxValue)
                .Select(s => s.Value.Job)
                .Concat(api.ScheduledJobs(0, int.MaxValue).Select(s => s.Value.Job));

            return processingJob.Any(j => j.Method.Name == jobMethodName);
        }
    }
}

using Newtonsoft.Json;

namespace Cve.Net.Search.Domain.Database.Extensions
{
    public static class ObjectExtensions
    {
        /// <summary>
        /// Check if objects are equals
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="firstObj"></param>
        /// <param name="secondObj"></param>
        /// <returns></returns>
        public static bool ObjectsAreEqual<T>(T firstObj, T secondObj)
        {
            var objFirstSerialized = JsonConvert.SerializeObject(firstObj);
            var objSecondSerialized = JsonConvert.SerializeObject(secondObj);

            return objFirstSerialized == objSecondSerialized;
        }
    }
}

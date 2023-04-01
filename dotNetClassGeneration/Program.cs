using NJsonSchema;
using NJsonSchema.CodeGeneration.CSharp;
using System.IO;
using System.Threading.Tasks;

namespace dotNetClassGeneration
{
    internal class Program
    {
        private static async Task Main(string[] args)
        {
            var schemaFromFile = await JsonSchema.FromUrlAsync(args[0]);
            var classGenerator = new CSharpGenerator(schemaFromFile, new CSharpGeneratorSettings
            {
                ClassStyle = CSharpClassStyle.Poco,
            });
            var codeFile = classGenerator.GenerateFile();
            File.WriteAllText("CustomClass.cs", codeFile);
        }
    }
}
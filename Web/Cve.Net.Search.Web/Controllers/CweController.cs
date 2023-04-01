using AutoMapper;
using Cve.Application.Services;
using Cve.Net.Search.Domain.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace CVESearch.Controllers
{
    [Route("cwe")]
    public class CweController : Controller
    {
        private readonly ICweMongoService _cweMongoService;
        private readonly IMapper _mapper;

        public CweController(ICweMongoService cweMongoService, IMapper mapper)
        {
            _cweMongoService = cweMongoService;
            _mapper = mapper;
        }

        /// <summary>
        /// Search CWE by Id
        /// </summary>
        /// <param name="cweId">ID of CWE (ex. 1001)</param>
        /// <returns></returns>
        [HttpGet("{cweId}")]
        [ProducesResponseType(typeof(CweViewModel), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> Get(int cweId)
        {
            var cwe = await _cweMongoService.Get(cweId.ToString());

            if (cwe == null)
                return NotFound($"CWE-{cweId} is not found");

            return Ok(_mapper.Map<CweViewModel>(cwe));
        }
    }
}

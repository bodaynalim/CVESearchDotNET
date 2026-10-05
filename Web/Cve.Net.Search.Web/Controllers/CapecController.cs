using AutoMapper;
using Cve.Application.Services;
using Cve.Net.Search.Domain.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;

namespace CVESearch.Controllers;

[ApiController]
[Route("capec")]
public class CapecController : Controller
{
    private readonly ICapecMongoService _capecMongoService;
    private readonly IMapper _mapper;

    public CapecController(ICapecMongoService capecMongoService, IMapper mapper)
    {
        _capecMongoService = capecMongoService;
        _mapper = mapper;
    }

    /// <summary>
    /// Search CAPEC by Id
    /// </summary>
    /// <param name="capecId">ID of CAPEC (ex. 1)</param>
    /// <returns></returns>
    [HttpGet("{capecId}")]
    [ProducesResponseType(typeof(CapecViewModel), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Get([FromRoute][Range(1, int.MaxValue)] int capecId, CancellationToken cancellationToken)
    {
        var capec = await _capecMongoService.Get(capecId.ToString(), cancellationToken);

        if (capec == null)
            return NotFound($"CAPEC-{capecId} is not found");

        return Ok(_mapper.Map<CapecViewModel>(capec));
    }
}

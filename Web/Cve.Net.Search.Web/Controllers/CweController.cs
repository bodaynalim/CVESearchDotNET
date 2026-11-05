using AutoMapper;
using Cve.Application.Services;
using Cve.Net.Search.Domain.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;

namespace CVESearch.Controllers;

[ApiController]
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
    /// Count all CWE entries
    /// </summary>
    [HttpGet("all/count")]
    [ProducesResponseType(typeof(CweSearchCountViewModel), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CountAll(CancellationToken cancellationToken)
    {
        var total = await _cweMongoService.CountCwes(null, cancellationToken);

        return Ok(new CweSearchCountViewModel { Total = total });
    }

    /// <summary>
    /// List all CWE entries, paged in ascending numeric-ID order
    /// </summary>
    /// <param name="count">Count per page</param>
    /// <param name="page">Page</param>
    /// <returns></returns>
    [HttpGet("all/{count}/{page}")]
    [ProducesResponseType(typeof(IEnumerable<CweViewModel>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ListAll(
        [FromRoute][Range(1, int.MaxValue)] int count,
        [FromRoute][Range(1, int.MaxValue)] int page,
        CancellationToken cancellationToken)
    {
        var (cwes, _) = await _cweMongoService.GetCweList(null, count, page, cancellationToken);

        return Ok(cwes.Select(c => _mapper.Map<CweViewModel>(c)));
    }

    /// <summary>
    /// Count CWE entries whose ID or name contains the keyword
    /// </summary>
    /// <param name="keyword">Search phrase (a "CWE-" prefix is ignored)</param>
    [HttpGet("search-count/{keyword}")]
    [ProducesResponseType(typeof(CweSearchCountViewModel), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CountByKeyword(
        [FromRoute][Required][MinLength(1)] string keyword,
        CancellationToken cancellationToken)
    {
        var total = await _cweMongoService.CountCwes(NormalizeKeyword(keyword), cancellationToken);

        return Ok(new CweSearchCountViewModel { Total = total });
    }

    /// <summary>
    /// List CWE entries whose ID or name contains the keyword (case-insensitive), paged
    /// </summary>
    /// <param name="keyword">Search phrase (a "CWE-" prefix is ignored)</param>
    /// <param name="count">Count per page</param>
    /// <param name="page">Page</param>
    /// <returns></returns>
    [HttpGet("search/{keyword}/{count}/{page}")]
    [ProducesResponseType(typeof(IEnumerable<CweViewModel>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> SearchByKeyword(
        [FromRoute][Required][MinLength(1)] string keyword,
        [FromRoute][Range(1, int.MaxValue)] int count,
        [FromRoute][Range(1, int.MaxValue)] int page,
        CancellationToken cancellationToken)
    {
        var (cwes, _) = await _cweMongoService.GetCweList(NormalizeKeyword(keyword), count, page, cancellationToken);

        return Ok(cwes.Select(c => _mapper.Map<CweViewModel>(c)));
    }

    private static string NormalizeKeyword(string keyword)
    {
        var trimmed = keyword.Trim();
        return trimmed.StartsWith("CWE-", StringComparison.OrdinalIgnoreCase)
            ? trimmed[4..]
            : trimmed;
    }

    /// <summary>
    /// Search CWE by Id
    /// </summary>
    /// <param name="cweId">ID of CWE (ex. 1001)</param>
    /// <returns></returns>
    [HttpGet("{cweId}")]
    [ProducesResponseType(typeof(CweViewModel), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Get([FromRoute][Range(1, int.MaxValue)] int cweId, CancellationToken cancellationToken)
    {
        var cwe = await _cweMongoService.Get(cweId.ToString(), cancellationToken);

        if (cwe == null)
            return NotFound($"CWE-{cweId} is not found");

        return Ok(_mapper.Map<CweViewModel>(cwe));
    }
}

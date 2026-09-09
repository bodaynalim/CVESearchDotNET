using AutoMapper;
using Cve.Infrastructure.Extensions;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CVESearch.Controllers;

[ApiController]
[Route("cve")]
public class CveController : Controller
{
    private readonly ICveMongoService _cveMongoService;
    private readonly IMapper _mapper;

    public CveController(ICveMongoService cveMongoService, IMapper mapper)
    {
        _cveMongoService = cveMongoService;
        _mapper = mapper;
    }

    /// <summary>
    /// Search CVEs by vendor and product
    /// </summary>
    /// <param name="vendor">Vulnerable vendor</param>
    /// <param name="product">Vulnerable product</param>
    /// <param name="count">Count of cves</param>
    /// <param name="page">Page</param>
    /// <param name="descending">True if order by descending</param>
    /// <param name="byPublished">True if order by published date (else by modified date)</param>
    /// <returns></returns>
    [HttpGet("search/{vendor}/{product}/{count}/{page}/{descending}/{byPublished}")]
    [ProducesResponseType(typeof(IEnumerable<CveViewModel>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Search(
        [FromRoute][Required] string vendor,
        [FromRoute][Required] string product,
        [FromRoute][Range(1, int.MaxValue)] int count,
        [FromRoute][Range(1, int.MaxValue)] int page,
        [FromRoute] bool descending,
        [FromRoute] bool byPublished,
        CancellationToken cancellationToken)
    {
        vendor = vendor.ReplaceNullCheck("%2F", "/");
        product = product.ReplaceNullCheck("%2F", "/");

        var cves = await _cveMongoService.GetCveList(vendor, product, count, page, descending, byPublished, cancellationToken);

        return Ok(cves.Select(c => _mapper.Map<CveViewModel>(c)));
    }

    /// <summary>
    /// Get CVE by ID
    /// </summary>
    /// <param name="cveId">CVE ID (ex. CVE-2018-0001)</param>
    /// <returns></returns>
    [HttpGet("{cveId}")]
    [ProducesResponseType(typeof(CveViewModel), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Get([FromRoute][Required] string cveId, CancellationToken cancellationToken)
    {
        var cve = await _cveMongoService.Get(cveId, cancellationToken);

        if (cve == null)
            return NotFound($"{cveId} is not found");

        return Ok(_mapper.Map<CveViewModel>(cve));
    }

    /// <summary>
    /// Get last CVE ID by published date for vendor and product
    /// </summary>
    /// <param name="vendor">Vulnerable vendor</param>
    /// <param name="product">Vulnerable product</param>
    /// <returns></returns>
    [HttpGet("last/published/{vendor}/{product}")]
    [ProducesResponseType(typeof(CveViewModel), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetLastPublished(
        [FromRoute][Required] string vendor,
        [FromRoute][Required] string product,
        CancellationToken cancellationToken)
    {
        vendor = vendor.ReplaceNullCheck("%2F", "/");
        product = product.ReplaceNullCheck("%2F", "/");

        var cve = await _cveMongoService.GetLastOnePublished(vendor, product, cancellationToken);

        if (cve == null)
            return NotFound($"CVE for {vendor} {product} is not found");

        return Ok(_mapper.Map<CveViewModel>(cve));
    }

    /// <summary>
    ///  Get last CVE ID by modified date for vendor and product
    /// </summary>
    /// <param name="vendor">Vulnerable vendor</param>
    /// <param name="product">Vulnerable product</param>
    /// <returns></returns>
    [HttpGet("last/modified/{vendor}/{product}")]
    [ProducesResponseType(typeof(CveViewModel), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetLastModified(
        [FromRoute][Required] string vendor,
        [FromRoute][Required] string product,
        CancellationToken cancellationToken)
    {
        vendor = vendor.ReplaceNullCheck("%2F", "/");
        product = product.ReplaceNullCheck("%2F", "/");

        var cve = await _cveMongoService.GetLastOneModified(vendor, product, cancellationToken);

        if (cve == null)
            return NotFound($"CVE for {vendor} {product} is not found");

        return Ok(_mapper.Map<CveViewModel>(cve));
    }
}

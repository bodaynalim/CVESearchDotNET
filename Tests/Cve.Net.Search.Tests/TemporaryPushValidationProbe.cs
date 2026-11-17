using Xunit;

namespace Cve.Net.Search.Tests;

// Temporary probe (T09+T13): intentionally failing test to demonstrate that
// the pre-push hook rejects a push of invalid code. Removed right after the demo.
public class TemporaryPushValidationProbe
{
    [Fact]
    public void Deliberately_fails_to_demonstrate_pre_push_gate()
    {
        Assert.True(false, "T09+T13 demo probe: this must fail on pre-push");
    }
}

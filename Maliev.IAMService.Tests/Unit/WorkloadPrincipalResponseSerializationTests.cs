using System.Text.Json;
using Maliev.IAMService.Application.DTOs.Responses;

namespace Maliev.IAMService.Tests.Unit;

public sealed class WorkloadPrincipalResponseSerializationTests
{
    [Fact]
    public void Serialize_BindingsMetadata_IsAdditiveAndPreservesPrimaryRoleId()
    {
        var principalId = Guid.NewGuid();
        var response = new WorkloadPrincipalResponse
        {
            WorkloadId = "contact-service",
            PrincipalId = principalId,
            ProfileVersion = 1,
            RoleId = "roles.workloads.contact-service.v1",
            Bindings =
            [
                new WorkloadPrincipalBindingResponse
                {
                    RoleId = "roles.workloads.contact-service.v1",
                    ResourcePath = null
                },
                new WorkloadPrincipalBindingResponse
                {
                    RoleId = "roles.workloads.contact-service.v1.upload-contacts",
                    ResourcePath = "folders/contacts"
                }
            ]
        };

        using var document = JsonDocument.Parse(JsonSerializer.Serialize(response, JsonSerializerOptions.Web));
        var root = document.RootElement;
        Assert.Equal("roles.workloads.contact-service.v1", root.GetProperty("roleId").GetString());
        var bindings = root.GetProperty("bindings");
        Assert.Equal(2, bindings.GetArrayLength());
        Assert.Equal("roles.workloads.contact-service.v1", bindings[0].GetProperty("roleId").GetString());
        Assert.Equal(JsonValueKind.Null, bindings[0].GetProperty("resourcePath").ValueKind);
        Assert.Equal("folders/contacts", bindings[1].GetProperty("resourcePath").GetString());
    }

    [Fact]
    public void Deserialize_LegacyPayloadWithoutBindings_DefaultsToEmptyBindings()
    {
        var principalId = Guid.NewGuid();
        var json = $$"""
            {
              "workloadId": "auth-service",
              "principalId": "{{principalId:D}}",
              "profileVersion": 1,
              "roleId": "roles.workloads.auth-service.v1"
            }
            """;

        var response = JsonSerializer.Deserialize<WorkloadPrincipalResponse>(json, JsonSerializerOptions.Web);

        Assert.NotNull(response);
        Assert.Equal("roles.workloads.auth-service.v1", response.RoleId);
        Assert.Empty(response.Bindings);
    }
}

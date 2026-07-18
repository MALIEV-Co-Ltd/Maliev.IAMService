using Maliev.IAMService.Application.Validators;

namespace Maliev.IAMService.Tests.Unit;

public class PermissionFormatValidatorTests
{
    [Theory]
    [InlineData("iam.principals.create", true)]
    [InlineData("storage.buckets.read", true)]
    [InlineData("service.resource.action", true)]
    [InlineData("abc.def.ghi", true)]
    [InlineData("a.b.c", true)]
    [InlineData("my-service.my-resource.update", true)]
    [InlineData("test-123.read-456.write-789", true)]
    public void IsValid_ValidPermissionIds_ReturnsTrue(string permissionId, bool expected)
    {
        var result = PermissionFormatValidator.IsValid(permissionId);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("invalid")]
    [InlineData("invalid.permission")]
    [InlineData("Invalid.Uppercase.action")]
    [InlineData("invalid.UPPERCASE.action")]
    [InlineData("invalid_permission.create")]
    [InlineData("invalid permission.create")]
    [InlineData("service..action")]
    [InlineData(".service.action")]
    [InlineData("service.action.")]
    [InlineData("service. .action")]
    [InlineData("service .resource.action")]
    [InlineData("service.resource. ")]
    [InlineData(" ")]
    public void IsValid_InvalidPermissionIds_ReturnsFalse(string? permissionId)
    {
        var result = PermissionFormatValidator.IsValid(permissionId!);
        Assert.False(result);
    }

    [Fact]
    public void Parse_ValidPermissionId_ReturnsComponents()
    {
        var (service, resource, action) = PermissionFormatValidator.Parse("iam.principals.create");

        Assert.Equal("iam", service);
        Assert.Equal("principals", resource);
        Assert.Equal("create", action);
    }

    [Fact]
    public void Parse_ValidPermissionId_WithHyphens_ReturnsComponents()
    {
        var (service, resource, action) = PermissionFormatValidator.Parse("my-service.my-resource.update");

        Assert.Equal("my-service", service);
        Assert.Equal("my-resource", resource);
        Assert.Equal("update", action);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("invalid")]
    [InlineData("Invalid.Uppercase.action")]
    public void Parse_InvalidPermissionId_ThrowsArgumentException(string? invalidId)
    {
        Assert.Throws<ArgumentException>(() => PermissionFormatValidator.Parse(invalidId!));
    }
}

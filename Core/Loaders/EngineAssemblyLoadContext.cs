using System;
using System.Reflection;
using System.Runtime.Loader;
using SerpiumVPN.Core.Interfaces;

namespace SerpiumVPN.Core;

/// <summary>
/// Resolves dependencies from an engine package while sharing the Serpium contract assembly
/// with the default process context so IEngine keeps a single type identity.
/// </summary>
internal sealed class EngineAssemblyLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver _resolver;
    private readonly Assembly _contractAssembly;

    public EngineAssemblyLoadContext(string engineId, string mainAssemblyPath)
        : base($"Serpium.Engine.{engineId}.{Guid.NewGuid():N}", isCollectible: false)
    {
        _resolver = new AssemblyDependencyResolver(mainAssemblyPath);
        _contractAssembly = typeof(IEngine).Assembly;
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        if (AssemblyName.ReferenceMatchesDefinition(
                assemblyName,
                _contractAssembly.GetName()))
        {
            return _contractAssembly;
        }

        string? assemblyPath = _resolver.ResolveAssemblyToPath(assemblyName);
        return assemblyPath is null
            ? null
            : LoadFromAssemblyPath(assemblyPath);
    }

    protected override nint LoadUnmanagedDll(string unmanagedDllName)
    {
        string? libraryPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        return libraryPath is null
            ? nint.Zero
            : LoadUnmanagedDllFromPath(libraryPath);
    }
}

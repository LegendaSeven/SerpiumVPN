using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using SerpiumVPN.Core.Interfaces;

namespace SerpiumVPN.Core;

/// <summary>
/// Discovers external engine packages, loads their assemblies and registers IEngine instances.
/// One broken package is reported and skipped without terminating the Serpium runtime.
/// </summary>
public sealed class DynamicEngineLoader
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private readonly EngineRegistry _engineRegistry;
    private readonly string _engineRootDirectory;
    private readonly Action<string>? _log;
    private readonly HashSet<string> _loadedEngineIds =
        new(StringComparer.OrdinalIgnoreCase);

    public DynamicEngineLoader(
        EngineRegistry engineRegistry,
        string engineRootDirectory,
        Action<string>? log = null)
    {
        _engineRegistry = engineRegistry
            ?? throw new ArgumentNullException(nameof(engineRegistry));

        if (string.IsNullOrWhiteSpace(engineRootDirectory))
        {
            throw new ArgumentException(
                "Engine directory cannot be empty.",
                nameof(engineRootDirectory));
        }

        _engineRootDirectory = Path.GetFullPath(engineRootDirectory);
        _log = log;
    }

    public string EngineRootDirectory => _engineRootDirectory;

    public EngineDiscoveryResult DiscoverAndRegister()
    {
        var results = new List<EngineLoadResult>();

        try
        {
            Directory.CreateDirectory(_engineRootDirectory);
        }
        catch (Exception exception)
        {
            results.Add(new EngineLoadResult(
                "<engine-root>",
                _engineRootDirectory,
                EngineLoadStatus.Failed,
                DescribeException(exception)));

            WriteSummary(results);
            return new EngineDiscoveryResult(results);
        }

        string[] packageDirectories;

        try
        {
            packageDirectories = Directory
                .GetDirectories(_engineRootDirectory)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception exception)
        {
            results.Add(new EngineLoadResult(
                "<engine-root>",
                _engineRootDirectory,
                EngineLoadStatus.Failed,
                DescribeException(exception)));

            WriteSummary(results);
            return new EngineDiscoveryResult(results);
        }

        WriteLog(
            $"[Engines] Scanning: {_engineRootDirectory}; packages={packageDirectories.Length}.");

        foreach (string packageDirectory in packageDirectories)
        {
            string manifestPath = Path.Combine(
                packageDirectory,
                EngineContract.ManifestFileName);

            if (!File.Exists(manifestPath))
            {
                continue;
            }

            results.Add(LoadPackage(packageDirectory, manifestPath));
        }

        WriteSummary(results);
        return new EngineDiscoveryResult(results);
    }

    private EngineLoadResult LoadPackage(
        string packageDirectory,
        string manifestPath)
    {
        EngineManifest? manifest = null;

        try
        {
            string manifestJson = File.ReadAllText(manifestPath);
            manifest = JsonSerializer.Deserialize<EngineManifest>(
                manifestJson,
                ManifestJsonOptions);

            if (manifest is null)
            {
                throw new InvalidDataException("Engine manifest is empty.");
            }

            ValidateManifest(manifest);
            string engineId = manifest.Id.Trim();

            if (!manifest.Enabled)
            {
                WriteLog($"[Engines] Skipped disabled package: {engineId}.");
                return new EngineLoadResult(
                    engineId,
                    packageDirectory,
                    EngineLoadStatus.Skipped,
                    "The engine is disabled in manifest.json.");
            }

            if (_loadedEngineIds.Contains(engineId))
            {
                WriteLog($"[Engines] Already loaded: {engineId}.");
                return new EngineLoadResult(
                    engineId,
                    packageDirectory,
                    EngineLoadStatus.Skipped,
                    "An engine package with this id is already loaded.");
            }

            string assemblyPath = ResolveAssemblyPath(
                packageDirectory,
                manifest.Assembly);

            if (!File.Exists(assemblyPath))
            {
                throw new FileNotFoundException(
                    "Engine assembly was not found.",
                    assemblyPath);
            }

            var loadContext = new EngineAssemblyLoadContext(
                engineId,
                assemblyPath);

            Assembly assembly = loadContext.LoadFromAssemblyPath(assemblyPath);
            Type engineType = ResolveEngineType(assembly, manifest.EntryType);

            if (engineType.GetConstructor(Type.EmptyTypes) is null)
            {
                throw new InvalidOperationException(
                    $"Engine type '{engineType.FullName}' must expose a public parameterless constructor.");
            }

            if (Activator.CreateInstance(engineType) is not IEngine engine)
            {
                throw new InvalidOperationException(
                    $"Engine type '{engineType.FullName}' could not be instantiated as IEngine.");
            }

            if (engine.Info is null || string.IsNullOrWhiteSpace(engine.Info.Name))
            {
                throw new InvalidOperationException(
                    $"Engine type '{engineType.FullName}' returned invalid component metadata.");
            }

            _engineRegistry.Register(engine);
            _loadedEngineIds.Add(engineId);

            WriteLog(
                $"[Engines] Loaded: id={engineId}; name={engine.Info.Name}; version={engine.Info.Version}.");

            return new EngineLoadResult(
                engineId,
                packageDirectory,
                EngineLoadStatus.Loaded,
                "Engine loaded and registered.",
                engine.Info.Name);
        }
        catch (Exception exception)
        {
            string engineId = string.IsNullOrWhiteSpace(manifest?.Id)
                ? Path.GetFileName(packageDirectory)
                : manifest.Id.Trim();

            string message = DescribeException(exception);
            WriteLog($"[Engines] Failed: id={engineId}; error={message}");

            return new EngineLoadResult(
                engineId,
                packageDirectory,
                EngineLoadStatus.Failed,
                message);
        }
    }

    private static void ValidateManifest(EngineManifest manifest)
    {
        if (manifest.SchemaVersion != EngineContract.ManifestSchemaVersion)
        {
            throw new InvalidDataException(
                $"Unsupported manifest schema version '{manifest.SchemaVersion}'. " +
                $"Required: {EngineContract.ManifestSchemaVersion}.");
        }

        if (manifest.ApiVersion != EngineContract.ApiVersion)
        {
            throw new InvalidDataException(
                $"Incompatible engine API version '{manifest.ApiVersion}'. " +
                $"Required: {EngineContract.ApiVersion}.");
        }

        if (string.IsNullOrWhiteSpace(manifest.Id))
        {
            throw new InvalidDataException("Engine manifest id is required.");
        }

        string engineId = manifest.Id.Trim();

        if (engineId.Length > 100 ||
            engineId.Any(character =>
                !char.IsLetterOrDigit(character) &&
                character is not '-' and not '_' and not '.'))
        {
            throw new InvalidDataException(
                "Engine manifest id may contain only letters, digits, '.', '-' and '_'.");
        }

        if (string.IsNullOrWhiteSpace(manifest.Assembly))
        {
            throw new InvalidDataException("Engine assembly path is required.");
        }

        if (!string.Equals(
                Path.GetExtension(manifest.Assembly),
                ".dll",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Engine assembly must be a DLL file.");
        }
    }

    private static string ResolveAssemblyPath(
        string packageDirectory,
        string relativeAssemblyPath)
    {
        string packageRoot = Path
            .GetFullPath(packageDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
            Path.DirectorySeparatorChar;

        string assemblyPath = Path.GetFullPath(
            Path.Combine(packageRoot, relativeAssemblyPath));

        if (!assemblyPath.StartsWith(
                packageRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Engine assembly path must remain inside its package directory.");
        }

        return assemblyPath;
    }

    private static Type ResolveEngineType(
        Assembly assembly,
        string? configuredEntryType)
    {
        if (!string.IsNullOrWhiteSpace(configuredEntryType))
        {
            Type? configuredType = assembly.GetType(
                configuredEntryType.Trim(),
                throwOnError: false,
                ignoreCase: false);

            if (configuredType is null)
            {
                throw new TypeLoadException(
                    $"Configured engine type '{configuredEntryType}' was not found.");
            }

            ValidateEngineType(configuredType);
            return configuredType;
        }

        Type[] candidates = GetLoadableTypes(assembly)
            .Where(type =>
                type.IsClass &&
                !type.IsAbstract &&
                type.IsVisible &&
                typeof(IEngine).IsAssignableFrom(type))
            .ToArray();

        return candidates.Length switch
        {
            1 => candidates[0],
            0 => throw new TypeLoadException(
                "The assembly does not contain a public, non-abstract IEngine implementation."),
            _ => throw new TypeLoadException(
                "The assembly contains multiple IEngine implementations. " +
                "Specify entryType in manifest.json.")
        };
    }

    private static void ValidateEngineType(Type engineType)
    {
        if (!engineType.IsClass ||
            engineType.IsAbstract ||
            !engineType.IsVisible ||
            !typeof(IEngine).IsAssignableFrom(engineType))
        {
            throw new TypeLoadException(
                $"Configured type '{engineType.FullName}' is not a public, non-abstract IEngine implementation.");
        }
    }

    private static Type[] GetLoadableTypes(Assembly assembly)
    {
        try
        {
            return assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException exception)
        {
            string details = string.Join(
                " | ",
                exception.LoaderExceptions
                    .Where(loaderException => loaderException is not null)
                    .Select(loaderException => loaderException!.Message));

            throw new TypeLoadException(
                string.IsNullOrWhiteSpace(details)
                    ? "One or more engine types could not be loaded."
                    : details,
                exception);
        }
    }

    private static string DescribeException(Exception exception)
    {
        Exception current = exception;

        while (current is TargetInvocationException && current.InnerException is not null)
        {
            current = current.InnerException;
        }

        return $"{current.GetType().Name}: {current.Message}";
    }

    private void WriteSummary(IReadOnlyList<EngineLoadResult> results)
    {
        int loaded = results.Count(result => result.Status == EngineLoadStatus.Loaded);
        int skipped = results.Count(result => result.Status == EngineLoadStatus.Skipped);
        int failed = results.Count(result => result.Status == EngineLoadStatus.Failed);

        WriteLog(
            $"[Engines] Summary: found={results.Count}; loaded={loaded}; skipped={skipped}; failed={failed}.");
    }

    private void WriteLog(string message)
    {
        _log?.Invoke(message);
    }
}

# SerpiumVPN MVP5.3 — Component Registry and Loader

## Added

- `Core/ComponentRegistry.cs`
  - registers components;
  - blocks duplicate component names;
  - supports lookup by name and type.
- `Core/ComponentLoadResult.cs`
  - stores initialization totals.
- `Core/ComponentLoader.cs`
  - initializes registered components in order;
  - shuts them down in reverse order;
  - isolates failures so one component does not stop the remaining components;
  - accepts an optional logging callback.

## Scope

This MVP adds the component infrastructure only. It does not yet modify `App.xaml.cs`
or wrap Relay/Headscale as a component. Runtime bootstrap integration belongs to the next
small patch after the current application startup file is supplied for analysis.

## Expected verification

`dotnet build` completes with 0 errors. Existing warnings in Relay may remain unchanged.

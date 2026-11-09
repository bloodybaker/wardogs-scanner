namespace Wardogs.Scanner;

// Retained name for compatibility; this is identification only, never a gate.
public static class GameProcessGuard
{
    public static bool IsGameProcess(string name) =>
        name.Equals("Wardogs", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("Wardogs-", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("Wardogs_", StringComparison.OrdinalIgnoreCase);
}
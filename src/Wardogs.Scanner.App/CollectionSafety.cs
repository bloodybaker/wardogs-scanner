namespace Wardogs.Scanner;

public static class CollectionSafety
{
    public static string Reason(Exception ex) => Limit(ex.GetType().Name + ": " + ex.Message);
    public static string Limit(string text, int max = 500) => text.Replace('\0', ' ').Length <= max
        ? text.Replace('\0', ' ') : text.Replace('\0', ' ')[..max];
    public static ModuleResult Failure(string name, double started, Exception ex) =>
        new(name, "error", started, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d, 0, Reason(ex));

    public static async Task<T> RunAsync<T>(Func<Task<T>> collect, Func<Exception, T> failed)
    {
        try { return await collect(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return failed(ex); }
    }

    public static void Run(string name, Action collect, List<ModuleResult> modules, List<string> errors)
    {
        var started = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d;
        try { collect(); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            modules.RemoveAll(m => m.Name == name);
            modules.Add(Failure(name, started, ex));
            errors.Add(Limit(name + ": " + Reason(ex)));
        }
    }
}

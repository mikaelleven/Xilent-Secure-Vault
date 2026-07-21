using Xilent.VaultAgent.Services;

namespace Xilent.VaultAgent;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        string command = args.FirstOrDefault(argument => argument is "--show" or "--mount" or "--unmount" or "--settings") ?? "--show";
        using SingleInstanceService singleInstance = new();
        if (!singleInstance.IsPrimaryInstance)
        {
            SingleInstanceService.SendCommandAsync(command).GetAwaiter().GetResult();
            return;
        }

        ApplicationConfiguration.Initialize();
        using VaultAgentApplicationContext context = new();
        singleInstance.StartServer(context.HandleCommand);
        if (args.Length > 0) context.HandleCommand(command);
        Application.Run(context);
    }
}

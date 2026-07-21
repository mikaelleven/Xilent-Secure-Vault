using System.IO.Pipes;
using System.Text;

namespace Xilent.VaultAgent.Services;

public sealed class SingleInstanceService : IDisposable
{
    private const string MutexName = "Local\\Xilent.VaultAgent";
    private const string PipeName = "Xilent.VaultAgent.Command";
    private readonly Mutex _mutex;
    private CancellationTokenSource? _serverCancellation;

    public bool IsPrimaryInstance { get; }

    public SingleInstanceService()
    {
        _mutex = new Mutex(true, MutexName, out bool createdNew);
        IsPrimaryInstance = createdNew;
    }

    public void StartServer(Action<string> commandReceived)
    {
        if (!IsPrimaryInstance) return;
        _serverCancellation = new CancellationTokenSource();
        _ = ListenAsync(commandReceived, _serverCancellation.Token);
    }

    public static async Task<bool> SendCommandAsync(string command)
    {
        try
        {
            using NamedPipeClientStream client = new(".", PipeName, PipeDirection.Out, PipeOptions.Asynchronous);
            await client.ConnectAsync(1000);
            byte[] message = Encoding.UTF8.GetBytes(command);
            await client.WriteAsync(message);
            return true;
        }
        catch (TimeoutException) { return false; }
        catch (IOException) { return false; }
    }

    private static async Task ListenAsync(Action<string> commandReceived, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using NamedPipeServerStream server = new(PipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                await server.WaitForConnectionAsync(cancellationToken);
                byte[] buffer = new byte[64];
                int count = await server.ReadAsync(buffer, cancellationToken);
                string command = Encoding.UTF8.GetString(buffer, 0, count);
                commandReceived(command);
            }
            catch (OperationCanceledException) { break; }
            catch (IOException) { /* A failed client must not stop the server. */ }
        }
    }

    public void Dispose()
    {
        _serverCancellation?.Cancel();
        _serverCancellation?.Dispose();
        _mutex.Dispose();
    }
}

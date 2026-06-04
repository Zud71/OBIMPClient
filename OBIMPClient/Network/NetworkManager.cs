using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading.Tasks;
using OBIMPClient.Models;

namespace OBIMPClient.Network;

// ========================================================================
// NetworkManager — TCP-соединение и чтение/отправка OBIMP-пакетов
// ========================================================================

/// <summary>
/// Управляет TCP-соединением с OBIMP-сервером, читает и отправляет OBIMP-пакеты.
/// Реализует асинхронный цикл чтения с буферизацией, корректно обрабатывает
/// фрагментированные пакеты и мультиплексирует несколько пакетов в одном чтении.
/// 
/// Последовательность подключения (согласно спецификации):
/// 1. Connect(host, port) — устанавливает TCP-соединение, запускает цикл чтения
/// 2. SendRequest(packet) — увеличивает Sequence и RequestId, отправляет пакет
/// 3. PacketReceived — событие, вызываемое при получении пакета
/// 4. Disconnect(reason) — закрывает соединение, отменяет чтение
/// </summary>
public class NetworkManager : IDisposable
{
    /// <summary>TCP-клиент для соединения с сервером.</summary>
    private TcpClient? _tcpClient;

    /// <summary>Сетевой поток для чтения/записи данных.</summary>
    private NetworkStream? _stream;

    /// <summary>Объект синхронизации для потокобезопасной отправки пакетов.</summary>
    private readonly object _lockObj = new();

    /// <summary>Token source для отмены асинхронного чтения.</summary>
    private CancellationTokenSource? _readCts;

    /// <summary>Задача цикла чтения.</summary>
    private Task? _readTask;

    // ========================================================================
    // События
    // ========================================================================

    /// <summary>
    /// Событие: получен OBIMP-пакет от сервера.
    /// Пакет уже распарсен: Header (заголовок), Data (сырые данные), Wtlds (распарсенные wTLD).
    /// </summary>
    public event Action<ObimpPacket>? PacketReceived;

    /// <summary>Событие: установлено TCP-соединение с сервером. Аргумент — адрес "host:port".</summary>
    public event Action<string>? Connected;

    /// <summary>Событие: соединение закрыто. Аргумент — причина закрытия.</summary>
    public event Action<string>? Disconnected;

    /// <summary>Событие: произошла ошибка сети. Аргумент — текст ошибки.</summary>
    public event Action<string>? ErrorOccurred;

    // ========================================================================
    // Состояние
    // ========================================================================

    /// <summary>Флаг активного соединения.</summary>
    private volatile bool _isConnected;

    /// <summary>
    /// Счётчик порядковых номеров (Sequence). Увеличивается на 1 при каждой отправке пакета.
    /// Начальное значение — 0. Отправленные Sequence: 0, 1, 2, ...
    /// </summary>
    private int _seqCounter;

    /// <summary>
    /// true — соединение активно (TCP-соединение установлено, цикл чтения работает).
    /// </summary>
    public bool IsConnected => _isConnected;

    // ========================================================================
    // Подключение / Отключение
    // ========================================================================

    /// <summary>
    /// Устанавливает TCP-соединение с OBIMP-сервером и запускает асинхронный цикл чтения пакетов.
    /// 
    /// Согласно спецификации OBIMP, после подключения клиент обязан отправить CLI_HELLO (BEX 0x0001, subtype 0x0001)
    /// с именем аккаунта (или без имени для попытки регистрации).
    /// </summary>
    /// <param name="host">Имя хоста или IP-адрес OBIMP-сервера.</param>
    /// <param name="port">Порт OBIMP-сервера (по умолчанию 7023, безопасный — 7033).</param>
    /// <param name="ct">Токен отмены операции.</param>
    public void Connect(string host, int port, CancellationToken ct = default)
    {
        _tcpClient = new TcpClient();
        _tcpClient.ConnectAsync(host, port, ct).GetAwaiter().GetResult();
        _stream = _tcpClient.GetStream();
        _isConnected = true;
        _seqCounter = 0;
        Connected?.Invoke($"Connected to {host}:{port}");
        StartReading(ct);
    }

    /// <summary>
    /// Закрывает TCP-соединение, отменяет цикл чтения и генерирует событие Disconnected.
    /// </summary>
    /// <param name="reason">Причина отключения (для логирования и события Disconnected).</param>
    public void Disconnect(string reason = "Disconnected")
    {
        _isConnected = false;
        _readCts?.Cancel();
        try { _readTask?.Wait(1000); } catch { }
        _stream?.Close();
        _tcpClient?.Close();
        Disconnected?.Invoke(reason);
    }

    // ========================================================================
    // Отправка пакетов
    // ========================================================================

    /// <summary>
    /// Отправляет OBIMP-пакет на сервер через TCP-соединение.
    /// Пакет сериализуется в байтовый массив по формату: Header(17 bytes) + wTLD data.
    /// Все многобайтовые числа записываются в Big-Endian порядке.
    /// 
    /// Метод потокобезопасен — используется блокировка через _lockObj.
    /// </summary>
    /// <param name="packet">Пакет для отправки. Header.Sequence и Header.RequestId должны быть уже установлены.</param>
    /// <exception cref="InvalidOperationException">Выбрасывается, если соединение не установлено.</exception>
    public void SendPacket(ObimpPacket packet)
    {
        lock (_lockObj)
        {
            if (!_isConnected || _stream == null)
                throw new InvalidOperationException("Not connected");

            var bytes = SerializePacket(packet);
            _stream.Write(bytes, 0, bytes.Length);

            // Логирование отправляемого пакета
            ReadOnlySpan<byte> source = bytes.AsSpan(13, sizeof(int));
            int len = BinaryPrimitives.ReadInt32BigEndian(source);

            var wtlds = string.Join(", ", packet.Wtlds?.Select(w => $"{w.Type}:0x{w.Type:X4}({w.Data.Length})") ?? Array.Empty<string>());
            Debug.WriteLine($"[SENDING] BexType=0x{packet.Header.BexType:X4} Subtype=0x{packet.Header.BexSubtype:X4} DataLen={len} Seq={packet.Header.Sequence} ReqId={packet.Header.RequestId} WtldCount={packet.Wtlds?.Count ?? 0} wTLDs=[{wtlds}]");

            _stream.Flush();
        }
    }

    /// <summary>
    /// Отправляет запрос-пакет: автоматически устанавливает Sequence и RequestId,
    /// затем вызывает SendPacket.
    /// Sequence берётся из глобального счётчика (_seqCounter), RequestId = Sequence.
    /// Это стандартный паттерн для всех запросов клиента к серверу.
    /// </summary>
    /// <param name="packet">Пакет для отправки. Загололок заполняется автоматически.</param>
    public void SendRequest(ObimpPacket packet)
    {
        packet.Header.Sequence = (uint)Interlocked.Increment(ref _seqCounter) - 1;
        packet.Header.RequestId = packet.Header.Sequence;
        SendPacket(packet);
    }

    /// <summary>
    /// Сериализует OBIMP-пакет в байтовый массив.
    /// Формат: Header.Magic(1) + Header.Sequence(4) + Header.BexType(2) + Header.BexSubtype(2) +
    ///         Header.RequestId(4) + Header.DataLength(4) + wTLD data.
    /// Все многобайтовые числа в Big-Endian.
    /// </summary>
    /// <param name="packet">Пакет для сериализации.</param>
    /// <returns>Байтовый массив, готовый для записи в TCP-поток.</returns>
    private byte[] SerializePacket(ObimpPacket packet)
    {
        var headerBytes = Serializer.SerializeHeader(packet.Header);
        var dataBytes = Serializer.SerializeWtlds(packet.Wtlds);
        var result = new byte[headerBytes.Length + dataBytes.Length];
        Array.Copy(headerBytes, 0, result, 0, headerBytes.Length);
        Array.Copy(dataBytes, 0, result, headerBytes.Length, dataBytes.Length);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(13), (uint)dataBytes.Length);
        return result;
    }

    // ========================================================================
    // Чтение пакетов
    // ========================================================================

    /// <summary>
    /// Запускает фоновую задачу асинхронного чтения TCP-потока.
    /// Чтение происходит в непрерывном цикле с буфером 64 КБ.
    /// </summary>
    private void StartReading(CancellationToken ct)
    {
        _readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _readTask = Task.Run(() => ReadLoop(_readCts.Token), _readCts.Token);
    }

    /// <summary>
    /// Основной цикл чтения. Обрабатывает фрагментированные пакеты и мультиплексирует
    /// несколько пакетов, полученных в одном чтении TCP.
    /// 
    /// Алгоритм:
    /// 1. Читаем данные в буфер до завершения чтения или ошибки.
    /// 2. Если данных меньше HeaderSize (17 байт) — ждём следующую порцию.
    /// 3. Парсим заголовок из первых 17 байт оставшихся данных.
    /// 4. Если TotalLength (заголовок + данные) больше доступных данных — ждём.
    /// 5. Извлекаем пакет: заголовок + данные по смещению.
    /// 6. Распаршиваем wTLD из данных.
    /// 7. Вызываем событие PacketReceived.
    /// 8. Сдвигаем буфер, обрабатываем следующий пакет.
    /// </summary>
    private void ReadLoop(CancellationToken ct)
    {
        var buffer = new byte[665536];
        var bufPos = 0;

        while (!ct.IsCancellationRequested && _isConnected)
        {
            try
            {
                var read = _stream!.ReadAsync(buffer, bufPos, buffer.Length - bufPos, ct).Result;
                Debug.WriteLine("[DEBUG] Read =>" + read);

                // read == 0 означает, что сервер закрыл соединение (EOF)
                if (read == 0)
                {
                    _isConnected = false;
                    Disconnected?.Invoke("Server closed connection");
                    break;
                }
                bufPos += read;

                // Обрабатываем все полные пакеты из буфера
                int consumed = 0;
                while (bufPos >= ObimpConstants.HeaderSize)
                {
                    // Заголовок всегда находится в начале оставшихся данных (с позиции consumed)
                    var hdr = Serializer.DeserializeHeader(buffer);
                    if (hdr.TotalLength < 0) break;
                    if (bufPos < hdr.TotalLength) break;

                    Debug.WriteLine($"[DEBUG] TotalLength =>{hdr.TotalLength}, consumed =>{consumed}");

                    var pkt = new ObimpPacket
                    {
                        Header = hdr,
                        Data = new byte[hdr.DataLength]
                    };

                    if (hdr.DataLength > 0)
                    {
                        // Данные пакета находятся сразу после заголовка
                        var dataOffset = consumed + ObimpConstants.HeaderSize;
                        Array.Copy(buffer, dataOffset, pkt.Data, 0, hdr.DataLength);
                    }

                    if (hdr.DataLength > 0)
                        pkt.Wtlds = Serializer.DeserializeWtlds(pkt.Data);

                    Debug.WriteLine($"[DEBUG] About to invoke PacketReceived. BexType=0x{pkt.Header.BexType:X4} Subtype=0x{pkt.Header.BexSubtype:X4} DataLen={pkt.Header.DataLength}");
                    
                    try
                    {
                        PacketReceived?.Invoke(pkt);
                        Debug.WriteLine($"[DEBUG] PacketReceived invoked OK");
                    }
                    catch (Exception invokeEx)
                    {
                        Debug.WriteLine($"[DEBUG] PacketReceived Invoke FAILED: {invokeEx.Message}");
                        Debug.WriteLine($"[DEBUG] StackTrace: {invokeEx.StackTrace}");
                    }

                    // Сдвигаем буфер: удаляем обработанные байты
                    bufPos -= hdr.TotalLength;
                    consumed += hdr.TotalLength;
                    if (bufPos > 0)
                        Array.Copy(buffer, consumed, buffer, 0, bufPos);
                    consumed = 0; // Сбрасываем для следующей итерации
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                if (_isConnected)
                {
                    ErrorOccurred?.Invoke($"Read error: {ex.Message}");
                    _isConnected = false;
                    Disconnected?.Invoke(ex.Message);
                }
                break;
            }
        }
    }

    // ========================================================================
    // IDisposable
    // ========================================================================

    /// <summary>
    /// Освобождает ресурсы: закрывает соединение, отменяет чтение, освобождает TCP-клиент.
    /// </summary>
    public void Dispose()
    {
        if (_isConnected) Disconnect();
        _readCts?.Dispose();
        _tcpClient?.Dispose();
    }
}

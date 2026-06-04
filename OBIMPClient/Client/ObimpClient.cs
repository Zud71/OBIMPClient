using System.Buffers;
using System.Diagnostics;
using System.Text;
using OBIMPClient.Models;
using OBIMPClient.Network;
using OBIMPClient.Security;

namespace OBIMPClient.Client;

// ========================================================================
// ObimpClient — основной клиент протокола OBIMP
// ========================================================================
/// <summary>
/// Основной класс клиента OBIMP, управляющий сессией, авторизацией, контактами, сообщениями и присутствием.
///
/// Жизненный цикл клиента:
///   1. Connect(host, port) — TCP-подключение
///   2. SendHello(account) — отправка CLI_HELLO (BEX Common, subtype 0x0001)
///   3. Ожидание SRV_HELLO (BEX Common, subtype 0x0002) → извлечение ServerKey (wTLD 0x0002)
///   4. SendLogin(account, hash) — отправка CLI_LOGIN (BEX Common, subtype 0x0003)
///   5. Ожидание SRV_LOGIN_REPLY → проверка кода ошибки, извлечение списка BEX
///   6. Запрос параметров списка контактов (CL_CLI_PARAMS)
///   7. Запрос списка контактов (CL_CLI_REQUEST)
///   8. Настройка presence (PRES_CLI_SET_PRES_INFO, PRES_CLI_ACTIVATE)
///   9. Обработка входящих пакетов через OnPacketReceived
///
/// Состояния:
///   - Подключён: IsConnected = true (TCP-соединение установлено)
///   - Авторизован: IsLoggedIn = true (CLI_LOGIN принят сервером)
///   - Список контактов загружен: _contacts заполнен
/// </summary>
public partial class ObimpClient
{
    /// <summary>Сетевой менеджер для TCP-соединения и отправки/получения пакетов.</summary>
    private readonly NetworkManager _net;

    /// <summary>Имя текущего аккаунта (lowercase). Заполняется при LoginAsync.</summary>
    private string? _myAccount;
    private string? _myPassword;

    /// <summary>
    /// Счётчик уникальных ID сообщений. Увеличивается на 1 при каждой отправке сообщения.
    /// Начальное значение — 1. Не должен быть нулём, иначе сервер закроет соединение.
    /// </summary>
    private ulong _msgIdCounter = 1;

    /// <summary>
    /// Серверный ключ (Server Key), полученный в SRV_HELLO (wTLD 0x0002).
    /// Используется для хеширования пароля (PasswordHasher).
    /// </summary>
    private byte[]? _serverKey;

    /// <summary>Загруженный список контактов. Ключ — Item ID, значение — Contact.</summary>
    private Dictionary<ulong, Contact> _contacts = new();

    /// <summary>Список офлайн-контактов (загруженный из CL_CLI_REQUEST, но не онлайн).</summary>
    private Dictionary<ulong, Contact> _offlineContacts = new();

    /// <summary>Маппинг Group ID → имя группы. Используется для восстановления имён групп при обновлении списка.</summary>
    private Dictionary<ulong, string> _groupMap = new();

    /// <summary>Активные сессии чата. Ключ — ID контакта.</summary>
    private List<ChatSession> _chatSessions = new();

    // ========================================================================
    // События
    // ========================================================================

    /// <summary>
    /// Событие: обновление статуса (логирование). Аргументы: уровень, сообщение.
    /// Вызывается при подключении, отключении, ошибках, уведомлениях.
    /// </summary>
    public event Action<string>? StatusMessage;

    /// <summary>
    /// Событие: список контактов обновлён. Аргументы: действие, контакт.
    /// Действие: "Added", "Updated", "Deleted".
    /// </summary>
    public event Action<string, Contact>? ContactListUpdated;

    /// <summary>
    /// Событие: получено сообщение. Аргументы: имя отправителя, имя получателя, объект сообщения.
    /// </summary>
    public event Action<string, string, ChatMessage>? MessageReceived;

    /// <summary>
    /// Событие: изменилось присутствие контакта. Аргументы: контакт, IsOnline, PresenceStatus, StatusName.
    /// </summary>
    public event Action<Contact, bool, uint, string>? ContactPresenceChanged;

    /// <summary>
    /// Событие: получен запрос авторизации. Аргументы: имя отправителя, причина.
    /// Вызывается при получении BEX CL_CLI_SRV_AUTH_REQUEST от другого контакта.
    /// </summary>
    public event Action<string, string, string>? AuthorizationRequestReceived;

    /// <summary>
    /// Событие: получен ответ на запрос авторизации. Аргументы: имя контакта, true = принят, false = отклонён.
    /// Вызывается при получении BEX CL_CLI_SRV_AUTH_REPLY.
    /// </summary>
    public event Action<string, bool>? AuthorizationReplyReceived;

    /// <summary>
    /// Событие: контакт отозвал авторизацию. Аргументы: имя контакта, причина.
    /// Вызывается при получении BEX CL_CLI_SRV_AUTH_REVOKE.
    /// </summary>
    public event Action<string, string>? AuthorizationRevokedReceived;

    /// <summary>
    /// Событие: сессия изменилась. Аргументы: имя аккаунта, IsLoggedIn.
    /// </summary>
    public event Action<string, bool>? SessionChanged;

    // ========================================================================
    // Состояние сессии
    // ========================================================================

    /// <summary>
    /// Имя текущего авторизованного аккаунта. null до авторизации.
    /// </summary>
    public string? MyAccount => _myAccount;

    /// <summary>
    /// true — клиент успешно авторизован (CLI_LOGIN принят, IsLoggedIn установлен сервером).
    /// false — клиент не авторизован или отключён.
    /// </summary>
    public bool IsLoggedIn { get; private set; }

    /// <summary>
    /// Загруженный список контактов (только для чтения). Ключ — Item ID, значение — Contact.
    /// </summary>
    public IReadOnlyDictionary<ulong, Contact> Contacts => _contacts;

    /// <summary>
    /// Активные сессии чата (только для чтения).
    /// </summary>
    public IReadOnlyList<ChatSession> ChatSessions => _chatSessions;

    // ========================================================================
    // Конструктор и подключение
    // ========================================================================

    /// <summary>
    /// Создаёт экземпляр клиента и подписывается на события NetworkManager.
    /// </summary>
    public ObimpClient()
    {
        _net = new NetworkManager();
        _net.PacketReceived += OnPacketReceived;
        Debug.WriteLine("[DEBUG] ObimpClient constructed, OnPacketReceived subscribed");
        _net.Connected += h => StatusMessage?.Invoke($"Connected: {h}");
        _net.Disconnected += r => { IsLoggedIn = false; StatusMessage?.Invoke($"Disconnected: {r}"); };
        _net.ErrorOccurred += e => StatusMessage?.Invoke($"Error: {e}");
    }

    /// <summary>
    /// Устанавливает TCP-соединение с OBIMP-сервером.
    /// </summary>
    /// <param name="host">Имя хоста или IP-адрес сервера.</param>
    /// <param name="port">Порт сервера (7023 по умолчанию).</param>
    public void Connect(string host, int port) => _net.Connect(host, port);

    /// <summary>
    /// Закрывает TCP-соединение и сбрасывает состояние сессии.
    /// </summary>
    public void Disconnect() => _net.Disconnect();

    // ========================================================================
    // HELLO — начальное приветствие
    // ========================================================================

    /// <summary>
    /// Отправляет CLI_HELLO (BEX 0x0001, subtype 0x0001) серверу.
    /// Это первый пакет, отправляемый после TCP-подключения.
    /// Содержит имя аккаунта (wTLD 0x0001, UTF8). Если аккаунт пуст — сервер может предложить регистрацию.
    /// </summary>
    /// <param name="account">Имя аккаунта (или пустая строка для регистрации).</param>
    private void SendHello(string account)
    {
        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexCommon,
                BexSubtype = ObimpConstants.BexComCliHello
            },

            Wtlds = new() { Serializer.Utf8Wtld(ObimpConstants.WtldComCliAccountName, account) }
        };
        // Исправлена опечатка в исходном коде: Sen dRequest -> SendRequest
        _net.SendRequest(pkt);
    }

    // ========================================================================
    // REGISTER — регистрация нового аккаунта
    // ========================================================================

    /// <summary>
    /// Отправляет CLI_REGISTER (BEX 0x0001, subtype 0x0008) для регистрации нового аккаунта.
    /// Регистрировать через протокол не рекомендуется для публичных IM-серверов.
    /// Регистрация может требовать административный ключ (wTLD 0x0004, BLK).
    /// </summary>
    /// <param name="account">Имя аккаунта для регистрации (UTF-8).</param>
    /// <param name="password">Пароль (UTF-8, max 1024 символов).</param>
    /// <param name="email">Безопасный email (UTF-8, optional).</param>
    public async Task RegisterAsync(string account, string password, string email)
    {
        SendHello(account);

        var tcs = new TaskCompletionSource<bool>();
        void Handler(ObimpPacket pkt)
        {
            // Исправлена опечатка в исходном коде: & & -> &&
            if (pkt.Header.BexSubtype == ObimpConstants.BexComSrvHello && pkt.Header.BexType == ObimpConstants.BexCommon)
            {
                var enabled = pkt.Wtlds.Any(w => w.Type == ObimpConstants.WtldComRegistrationEnabled);
                tcs.SetResult(enabled);
            }
        }

        _net.PacketReceived -= OnPacketReceived;
        _net.PacketReceived += Handler;

        await Task.Delay(ObimpConstants.RegistrationTimeoutMs); // Wait for response

        _net.PacketReceived -= Handler;
        _net.PacketReceived += OnPacketReceived;
    }

    // ========================================================================
    // LOGIN — авторизация
    // ========================================================================

    /// <summary>
    /// Выполняет полную процедуру входа в OBIMP:
    /// 1. Устанавливает TCP-соединение (Connect)
    /// 2. Отправляет CLI_HELLO с именем аккаунта
    /// 3. Ожидает SRV_HELLO извлекает ServerKey (wTLD 0x0002)
    /// 4. Хеширует пароль через PasswordHasher.GenerateHash()
    /// 5. Отправляет CLI_LOGIN с именем аккаунта и MD5-хэшем пароля (wTLD 0x0002, BLK)
    /// 
    /// После успешного входа IsLoggedIn = true, MyAccount заполнен.
    /// При получении кода ошибки сервер закроет соединение (BYE_REASON_NOT_ALLOWED).
    /// </summary>
    /// <param name="account">Имя аккаунта (UTF-8).</param>
    /// <param name="password">Пароль в открытом виде.</param>
    /// <param name="host">Имя хоста или IP-адрес OBIMP-сервера.</param>
    /// <param name="port">Порт OBIMP-сервера (7023 по умолчанию).</param>
    public async Task LoginAsync(string account, string password, string host, int port)
    {
        _myAccount = account;
        _myPassword = password;
        _msgIdCounter = 1;
        Connect(host, port);

        // Step 1: Send HELLO
        SendHello(account);

    }
}
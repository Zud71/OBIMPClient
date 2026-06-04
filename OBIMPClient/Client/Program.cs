using OBIMPClient.Models;
using System.Diagnostics;
using System.Text;

namespace OBIMPClient.Client;

/// <summary>
/// Точка входа консольного приложения — OBIMP Messenger Client.
/// Поддерживает два режима: автоматический вход (аргументы командной строки)
/// и интерактивный режим (автоматическое подключение с заданными учётными данными).
/// </summary>
class Program
{
    /// <summary>Экземпляр OBIMP-клиента.</summary>
    private static ObimpClient _client = new();

    /// <summary>Обратный маппинг: Item ID → имя аккаунта (для удобства работы в CLI).</summary>
    private static Dictionary<ulong, string> _contactLookup = new();

    /// <summary>Имя аккаунта текущего активного чата (пока не используется).</summary>
    private static string _currentChatAccount = null!;

    /// <summary>
    /// Точка входа. Обрабатывает аргументы командной строки:
    /// AutoLogin: args[0]=account, args[1]=password, args[2]=host, args[3]=port
    /// Иначе — InteractiveMode (жестко заданные тестовые учётные данные).
    /// </summary>
    static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.Title = "OBIMP Messenger Client";

        // Подписка на события клиента
        _client.StatusMessage += ShowStatus;
        _client.ContactListUpdated += (_, _) => RefreshContactList();
        _client.MessageReceived += (_, _, msg) => DisplayMessage(msg);
        _client.ContactPresenceChanged += (_, online, status, name) => ContactPresence(_, online, status, name);
        _client.SessionChanged += (_, _) => RefreshContactList();
        _client.AuthorizationRequestReceived += HandleAuthRequestReceived;
        _client.AuthorizationReplyReceived += HandleAuthReplyReceived;
        _client.AuthorizationRevokedReceived += HandleAuthRevokedReceived;

        Console.WriteLine("============================================");
        Console.WriteLine("   OBIMP Messenger Client v1.0");
        Console.WriteLine("============================================");
        Console.WriteLine();
        ShowHelp();

        if (args.Length >= 4)
        {
            await AutoLogin(args[0], args[1], args[2], int.Parse(args[3]));
            return;
        }

        // await InteractiveMode();
        await TestLogin();
    }

    // ========================================================================
    // Режимы подключения
    // ========================================================================

    /// <summary>
    /// Автоматический вход с аргументами командной строки:
    /// LoginAsync(account, password, host, port) → ожидание 10 сек → RequestServerParams → RequestContactList → ActivatePresence.
    /// </summary>
    static async Task AutoLogin(string account, string password, string host, int port)
    {
        Console.WriteLine($"Вход: {account}@{host}:{port}");
        await _client.LoginAsync(account, password, host, port);
        await Task.Delay(ObimpConstants.ServerHelloTimeoutMs);

        if (_client.IsLoggedIn)
        {
            _client.RequestContactList();
            _client.ActivatePresence();
            Console.WriteLine("Подключено. Введите 'exit' для выхода.");
            MainLoop();
        }
        else
        {
            Console.WriteLine("Ошибка входа.");
        }
    }

    /// <summary>
    /// Вход с жёстко заданными учётными данными для тестирования.
    /// В раскомментированной версии запрашивает account, password, host, port у пользователя.
    /// </summary>
    static async Task TestLogin()
    {
        string? account = null, password = null, host = null;
        int port = ObimpConstants.DefaultPort;

        account = "test";
        password = "test123";
        host = "localhost";

        Console.WriteLine($"Подключение к {host}:{port}...");
        await _client.LoginAsync(account!, password!, host!, port);
        await Task.Delay(ObimpConstants.ServerHelloTimeoutMs);

        if (_client.IsLoggedIn)
        {
            _client.RequestContactList();
            _client.ActivatePresence();
            Console.WriteLine("Подключено. Введите 'help' для списка команд.");
            MainLoop();
        }
        else
        {
            Console.WriteLine("Ошибка входа.");
        }
    }

    /// <summary>
    /// Интерактивный режим с жёстко заданными учётными данными для тестирования.
    /// В раскомментированной версии запрашивает account, password, host, port у пользователя.
    /// </summary>
    private static async Task InteractiveMode()
    {
        string? account = null;
        string? password = null;
        string? host = null;

        int port = ObimpConstants.DefaultPort;

        // Ввод имени учётной записи
        while (string.IsNullOrEmpty(account))
        {
            Console.Write("Аккаунт: ");
            account = Console.ReadLine();
        }

        // Ввод пароля (функция ReadPassword должна быть реализована отдельно)
        while (string.IsNullOrEmpty(password))
        {
            password = ReadPassword();
        }

        // Ввод адреса сервера
        while (string.IsNullOrEmpty(host))
        {
            Console.Write("Сервер (нажмите Enter для localhost): ");
            host = Console.ReadLine();
            if (string.IsNullOrEmpty(host))
            {
                host = "localhost";
            }
        }

        // Ввод порта (опционально)
        Console.Write($"Порт (нажмите Enter для значения по умолчанию {ObimpConstants.DefaultPort}): ");
        string? portInput = Console.ReadLine();
        if (!string.IsNullOrEmpty(portInput) && int.TryParse(portInput, out int customPort))
        {
            port = customPort;
        }

        Console.WriteLine($"Подключение к {host}:{port}...");
        await _client.LoginAsync(account!, password!, host!, port);

        await Task.Delay(ObimpConstants.ServerHelloTimeoutMs);

        if (_client.IsLoggedIn)
        {
            _client.RequestContactList();
            _client.ActivatePresence();
            Console.WriteLine("Подключено. Введите 'help' для списка команд.");
            MainLoop(); // Рекомендуется сделать MainLoop асинхронным
        }
        else
        {
            Console.WriteLine("Ошибка входа.");
        }
    }

    // ========================================================================
    // Интерактивный CLI (командная строка)
    // ========================================================================

    /// <summary>
    /// Главный цикл CLI. Читает команды от пользователя и вызывает соответствующие методы ObimpClient.
    static void MainLoop()
    {
        while (true)
        {
            Console.Write("OBIMP> ");
            var line = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(line)) continue;

            var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            var cmd = parts[0].ToLowerInvariant();
            var arg = parts.Length > 1 ? parts[1] : null;

            try
            {
                switch (cmd)
                {
                    case "help":
                    case "h": ShowHelp(); break;
                    case "exit":
                    case "quit":
                    case "q":
                        Console.WriteLine("Отключение...");
                        _client.Disconnect();
                        return;
                    case "connect":
                        if (arg != null)
                        {
                            var p = arg.Split(':');
                            var h = p[0];
                            var port = p.Length > 1 ? int.Parse(p[1]) : ObimpConstants.DefaultPort;
                            _client.Connect(h, port);
                        }
                        break;
                    case "logout":
                    case "dis":
                        _client.Disconnect();
                        break;
                    case "msg":
                    case "m":
                        if (arg != null)
                        {
                            var mp = arg.Split(';', 2);
                            if (mp.Length >= 2) _client.SendMessage(mp[0], mp[1]);
                        }
                        break;
                    case "typing":
                    case "t":
                        if (arg != null)
                        {
                            var parts2 = arg.Split(';', 2);
                            if (parts2.Length >= 1)
                                _client.SendTypingNotification(parts2[0], Convert.ToBoolean(parts2[1]));
                        }
                        break;
                    case "addcontact":
                    case "ac":
                        if (arg != null)
                        {
                            var ap = arg.Split(';', 2);
                            var name = ap.Length > 1 ? ap[1] : ap[0];
                            _client.AddContact(ap[0], name);
                        }
                        break;
                    case "delcontact":
                    case "dc":
                        if (arg != null && ulong.TryParse(arg, out var uid))
                            _client.DeleteContact(uid);
                        break;
                    case "addgroup":
                    case "ag":
                        if (arg != null) _client.AddGroup(arg);
                        break;
                    case "auth":
                    case "reqauth":
                        if (arg != null) _client.RequestAuthorization(arg, reason: "Authorization request");
                        break;
                    case "revoke":
                    case "revokeauth":
                        if (arg != null) _client.RevokeAuthorization(arg);
                        break;
                    case "list":
                    case "contacts":
                        // Парсинг аргументов: например, "list online" или "contacts online nogroups"
                        bool onlyOnline = arg != null && arg.Contains("online", StringComparison.OrdinalIgnoreCase);
                        bool showGroups = arg == null || !arg.Contains("nogroups", StringComparison.OrdinalIgnoreCase);
                        DisplayContactList(onlyOnline, showGroups);
                        break;
                    case "authaccept":
                    case "aa":
                        if (arg != null) _client.RespondToAuthRequest(arg, grant: true);
                        break;
                    case "authdeny":
                    case "ad":
                        if (arg != null) _client.RespondToAuthRequest(arg, grant: false);
                        break;
                    case "status":
                        if (arg != null)
                        {
                            var code = GetStatusCode(arg);
                            _client.SetStatus(code);
                        }
                        break;
                    default:
                        Console.WriteLine($"Неизвестная команда: {cmd}");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Выводит справку по доступным командам CLI.
    /// </summary>
    static void ShowHelp()
    {
        Console.WriteLine("\n=== Команды ===");
        Console.WriteLine("  help/h                    - Показать эту справку");
        Console.WriteLine("  connect host:port         - Подключиться к серверу");
        Console.WriteLine("  logout/dis                - Отключиться");
        Console.WriteLine("  msg <account>;<text>      - Отправить сообщение");
        Console.WriteLine("  typing <account>;<bool>   - Отправить уведомление о наборе текста");
        Console.WriteLine("  addcontact <account>;[display] - Добавить контакт");
        Console.WriteLine("  delcontact <id>           - Удалить контакт");
        Console.WriteLine("  addgroup <name>           - Добавить группу");
        Console.WriteLine("  auth <account>            - Запросить авторизацию");
        Console.WriteLine("  authaccept <account>      - Принять запрос авторизации");
        Console.WriteLine("  authdeny <account>        - Отклонить запрос авторизации");
        Console.WriteLine("  revoke <account>          - Отозвать авторизацию");
        Console.WriteLine("  list/contacts [online] [nogroups] - Показать список контактов (иерархически)");
        Console.WriteLine("  status <online|away|busy> - Установить статус присутствия");
        Console.WriteLine("  exit/q                    - Выйти");
        Console.WriteLine();
    }

    /// <summary>
    /// Получает числовой код статуса по текстовому имени.
    /// </summary>
    static uint GetStatusCode(string statusName)
    {
     /*   return statusName.ToLowerInvariant() switch
        {
            "online" => ObimpConstants.PresStatusOnline,
            "invisible" => ObimpConstants.PresStatusInvisible,
            "free" => ObimpConstants.PresStatusFreeForChat,
            "away" => ObimpConstants.PresStatusAway,
            "busy" or "occupied" => ObimpConstants.PresStatusOccupied,
            "dnd" or "donotdisturb" => ObimpConstants.PresStatusDoNotDisturb,
            _ => ObimpConstants.PresStatusOnline
        };*/

        if (ObimpClient.StatusCodes.TryGetValue(statusName.ToLowerInvariant(), out var code))
        {
            return code;
        }

        return ObimpConstants.PresStatusOnline;
    }

    /// <summary>
    /// Возвращает текстовое описание статуса по числовому коду.
    /// </summary>
    static string GetStatusText(uint status)
    {
        /* return status switch
         {
             ObimpConstants.PresStatusOnline => "В сети",
             ObimpConstants.PresStatusInvisible => "Невидимка",
             ObimpConstants.PresStatusFreeForChat => "Свободен для общения",
             ObimpConstants.PresStatusAway => "Отошёл",
             ObimpConstants.PresStatusOccupied => "Занят",
             ObimpConstants.PresStatusDoNotDisturb => "Не беспокоить",
             _ => "Неизвестно"
         };*/

        if (ObimpClient.StatusNames.TryGetValue(status, out var statusName))
        {
            return statusName;
        }

        return "Неизвестно";
    }

    // ========================================================================
    // Обработчики событий — вывод в консоль
    // ========================================================================

    /// <summary>
    /// Обработчик StatusMessage — отображает системные сообщения.
    /// </summary>
    static void ShowStatus(string msg) => Console.WriteLine($"  >>> {msg}");

    /// <summary>
    /// Обработчик ContactListUpdated — обновляет и отображает список контактов в Debug.
    /// Сортировка: по типу (группы, контакты, транспорты), затем по имени.
    /// Префиксы: [G] = группа, [+] = онлайн-контакт, [-] = офлайн-контакт, [T] = транспорт.
    /// </summary>
    static void RefreshContactList()
    {
        Debug.WriteLine($"\n=== Контакты ({_client.Contacts.Count}) ===");
        var sorted = _client.Contacts.Values.OrderBy(c => c.ItemType).ThenBy(c => c.DisplayName);
        foreach (var c in sorted)
        {
            var prefix = c.ItemType == ContactItemType.Group ? "[G]" :
                         c.ItemType == ContactItemType.Contact ?
                            (c.IsOnline ? "[+]" : "[-]") : "[T]";
            Debug.WriteLine($"  {prefix} {c.DisplayName} ({c.AccountName})");
        }
        Debug.WriteLine("");
    }

    /// <summary>
    /// Отображает список контактов в виде иерархии (дерева).
    /// </summary>
    /// <param name="onlyOnline">Если true, показывает только онлайн-контакты (и группы, в которых они есть).</param>
    /// <param name="showGroups">Если false, скрывает узлы групп, но показывает их содержимое.</param>
    static void DisplayContactList(bool onlyOnline = false, bool showGroups = true)
    {
        Console.WriteLine("\n=== Контакты ===");

        // 1. Предварительная фильтрация элементов
        var items = _client.Contacts.Values.ToList();
        if (onlyOnline)
        {
            // Оставляем только онлайн-контакты и элементы, не являющиеся контактами (группы, транспорты).
            // Пустые группы (без онлайн-контактов) будут автоматически скрыты на этапе рекурсии.
            items = items.Where(c => c.ItemType != ContactItemType.Contact || c.IsOnline).ToList();
        }

        // 2. Находим корневые элементы (у которых GroupId == 0)
        var rootItems = items
            .Where(c => c.GroupId == 0)
            .OrderBy(c => c.ItemType)
            .ThenBy(c => c.DisplayName)
            .ToList();

        // 3. Рекурсивный вывод дерева
        foreach (var root in rootItems)
        {
            PrintHierarchyItem(root, items, 0, showGroups);
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Рекурсивный вывод элемента списка контактов и его дочерних элементов.
    /// </summary>
    static void PrintHierarchyItem(Contact item, List<Contact> allItems, int indent, bool showGroups)
    {
        // Если это группа, проверяем, есть ли у неё видимые дочерние элементы
        if (item.ItemType == ContactItemType.Group)
        {
            var children = allItems.Where(c => c.GroupId == item.ItemId).ToList();
            if (children.Count == 0)
            {
                return; // Не выводим пустые группы (например, если all контакты в ней офлайн, а включён фильтр onlyOnline)
            }
        }

        // Если это группа и указано не выводить группы, пропускаем вывод самого узла группы, 
        // но выводим её дочерние элементы на текущем уровне отступа (чтобы не терять контакты).
        if (item.ItemType == ContactItemType.Group && !showGroups)
        {
            var children = allItems.Where(c => c.GroupId == item.ItemId)
                                   .OrderBy(c => c.ItemType)
                                   .ThenBy(c => c.DisplayName);
            foreach (var child in children)
            {
                PrintHierarchyItem(child, allItems, indent, showGroups);
            }
            return;
        }

        // Формирование префикса в зависимости от типа элемента
        string prefix = item.ItemType switch
        {
            ContactItemType.Group => "[G] ",
            ContactItemType.Contact => item.IsOnline ? "[+] " : "[-] ",
            ContactItemType.Transport => "[T] ",
            ContactItemType.Note => "[N] ",
            _ => "[?] "
        };

        // Формирование отступа и строки аккаунта
        string indentStr = new string(' ', indent * 2);
        string accountInfo = string.IsNullOrEmpty(item.AccountName) ? "" : $" ({item.AccountName})";

        Console.WriteLine($"{indentStr}{prefix}{item.DisplayName}{accountInfo}");

        // Рекурсивный обход дочерних элементов с увеличением уровня отступа
        var childItems = allItems.Where(c => c.GroupId == item.ItemId)
                                 .OrderBy(c => c.ItemType)
                                 .ThenBy(c => c.DisplayName);

        foreach (var child in childItems)
        {
            PrintHierarchyItem(child, allItems, indent + 1, showGroups);
        }
    }

    /// <summary>
    /// Обработчик MessageReceived — отображает полученное сообщение.
    /// Префикс: СИСТ = системное, ОФЛ = офлайн-сообщение, СООБЩ = обычное.
    /// </summary>
    static void DisplayMessage(ChatMessage msg)
    {
        var prefix = msg.IsSystemMessage ? "СИСТ" :
                     msg.IsOffline ? "ОФЛ" : "СООБЩ";
        Console.WriteLine($"\n {msg.ReceivedTime:HH:mm:ss}  [{prefix}] {msg.SenderAccount}: {msg.Text}");
    }

    /// <summary>
    /// Обработчик ContactPresenceChanged — обновляет отображение статуса контакта.
    /// </summary>
    static void ContactPresence(Contact contact, bool online, uint status, string statusName)
    {
        /*   var onlineStr = online ? "[+]" : "[-]";
             var statusText = GetStatusText(status);
             Console.WriteLine($"  [PRESENCE] {onlineStr} {contact.DisplayName} ({contact.AccountName}): {statusText}");
         */
    }

    // ========================================================================
    // Обработчики событий авторизации
    // ========================================================================

    /// <summary>
    /// Обработчик AuthorizationRequestReceived — получен запрос авторизации от другого пользователя.
    /// </summary>
    static void HandleAuthRequestReceived(string sender, string reason, string mode)
    {
        Console.WriteLine($"\n  [ЗАПРОС АВТОРИЗАЦИИ] {sender} хочет авторизовать вас (через {mode})");
        // Ответ: 'authaccept <account>' или 'authdeny <account>'
    }

    /// <summary>
    /// Обработчик AuthorizationReplyReceived — получен ответ на наш запрос авторизации.
    /// При Granted — обновляет IsAuthorized и обновляет список контактов.
    /// </summary>
    static void HandleAuthReplyReceived(string account, bool granted)
    {
        if (granted)
        {
            Console.WriteLine($"\n  [АВТОРИЗАЦИЯ ПРИНЯТА] {account} предоставил(а) вам авторизацию.");
            var contact = _client.Contacts.Values.FirstOrDefault(c => c.AccountName == account);
            if (contact != null)
            {
                contact.IsAuthorized = true;
                RefreshContactList();
            }
        }
        else
        {
            Console.WriteLine($"\n  [АВТОРИЗАЦИЯ ОТКЛОНЕНА] {account} отклонил(а) ваш запрос авторизации.");
        }
    }

    /// <summary>
    /// Обработчик AuthorizationRevokedReceived — авторизация отозвана контактом.
    /// Снимает IsAuthorized и обновляет список.
    /// </summary>
    static void HandleAuthRevokedReceived(string account, string reason)
    {
        Console.WriteLine($"\n  [АВТОРИЗАЦИЯ ОТОЗВАНА] {account} отозвал(а) вашу авторизацию. Причина: {reason}");
        var contact = _client.Contacts.Values.FirstOrDefault(c => c.AccountName == account);
        if (contact != null)
        {
            contact.IsAuthorized = false;
            RefreshContactList();
        }
    }

    // ========================================================================
    // Вспомогательные утилиты
    // ========================================================================

    /// <summary>
    /// Безопасное чтение пароля из консоли (символы не отображаются, заменяются на '*').
    /// </summary>
    static string ReadPassword()
    {
        Console.Write("Пароль: ");
        var sb = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
            if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
            { sb.Remove(sb.Length - 1, 1); Console.Write("\b \b"); }
            else if (key.KeyChar != 0) { sb.Append(key.KeyChar); Console.Write("*"); }
        }
        return sb.ToString();
    }
}
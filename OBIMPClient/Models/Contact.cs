using System.Collections.ObjectModel;

namespace OBIMPClient.Models;

// ========================================================================
// Типы элементов списка контактов (Contact List Item Types)
// ========================================================================

/// <summary>
/// Типы элементов списка контактов (BEX 0x0002, Contact List).
/// Определяют роль элемента при парсинге SRV_REPLY blob и при операциях ADD/DEL/UPD_ITEM.
/// </summary>
public enum ContactItemType
{
    /// <summary>Группа — контейнер для организации контактов. Может содержать подгруппы (Group ID != 0).</summary>
    Group = 0x0001,

    /// <summary>Контакт — основная единица списка. Содержит имя аккаунта, отображаемое имя, тип приватности, флаг авторизации.</summary>
    Contact = 0x0002,

    /// <summary>Транспорт — подключение внешнего мессенджера (Jabber, IRC, SMS и т.д.).</summary>
    Transport = 0x0003,

    /// <summary>Заметка — пользовательская заметка. Может быть текстовой, командой, ссылкой, email-адресом или телефоном.</summary>
    Note = 0x0004
}

// ========================================================================
// Типы приватности контактов (Contact Privacy Types)
// ========================================================================

/// <summary>
/// Типы приватности контактов (Privacy Types).
/// Определяют видимость контакта и доступ к его presence-информации.
/// Используется в sTLD 0x0004 элемента «Контакт».
/// </summary>
public enum ContactPrivacyType : byte
{
    /// <summary>Все видны: контакт виден всем, presence-информация доступна.</summary>
    None = 0x00,

    /// <summary>Видим для списка: контакт виден только пользователям из списка контактов данного контакта.</summary>
    VisibleList = 0x01,

    /// <summary>Невидим для списка: контакт не виден пользователям из списка контактов.</summary>
    InvisibleList = 0x02,

    /// <summary>Игнорировать всех: игнорировать сообщения и presence от всех контактов.</summary>
    IgnoreList = 0x03,

    /// <summary>Игнорировать не из списка: игнорировать всё, что не из списка контактов.
    /// При добавлении такого контакта Group ID должен быть всегда 0 (иначе сервер вернёт ошибку).</summary>
    IgnoreNotInList = 0x04
}

// ========================================================================
// Контакт (Contact Item)
// ========================================================================

/// <summary>
/// Элемент списка контактов (Contact List Item).
/// Соответствует универсальной структуре элемента, описанной в спецификации OBIMP (BEX 0x0002, SRV_REPLY).
/// 
/// Каждый элемент имеет уникальный Item ID и Group ID. Group ID = 0 означает отсутствие родительской группы.
/// Для группы Group ID указывает на родительскую группу (для подгрупп).
/// Флаг IsGeneral означает, что элемент добавлен/удалён только администратором.
/// </summary>
public class Contact
{
    /// <summary>
    /// Уникальный идентификатор элемента (Item ID). Генерируется сервером при добавлении.
    /// Уникален в пределах всего списка контактов.
    /// </summary>
    public ulong ItemId { get; set; }

    /// <summary>
    /// Идентификатор родительской группы (Group ID). 
    /// 0 — элемент не в группе. Для подгрупп — Group ID родительской группы.
    /// </summary>
    public ulong GroupId { get; set; }

    /// <summary>
    /// Тип элемента: группа, контакт, транспорт или заметка.
    /// </summary>
    public ContactItemType ItemType { get; set; }

    /// <summary>
    /// Имя аккаунта (только для типа Contact). UTF-8 строка, максимальная длина определяется
    /// в SRV_PARAMS_REPLY (wTLD 0x0004).
    /// </summary>
    public string AccountName { get; set; } = string.Empty;

    /// <summary>
    /// Отображаемое имя (Display Name). Для контакта — sTLD 0x0003, для группы — sTLD 0x0001,
    /// для транспорта — sTLD 0x1004 (friendly name). Максимальная длина определяется в SRV_PARAMS_REPLY (wTLD 0x0005).
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Флаг авторизации (только для типа Contact). 
    /// true — авторизационный флаг установлен (запрос на авторизацию отправлен).
    /// true может быть убран сервером автоматически после получения AUTH_REPLY_GRANTED.
    /// </summary>
    public bool IsAuthorized { get; set; }

    /// <summary>
    /// Флаг общего элемента (General Item Flag). 
    /// true — элемент добавлен/удалён только администратором сервера.
    /// </summary>
    public bool IsGeneral { get; set; }

    /// <summary>
    /// Тип приватности контакта (только для типа Contact).
    /// </summary>
    public ContactPrivacyType PrivacyType { get; set; }

    /// <summary>
    /// Статус онлайн/офлайн контакта. Обновляется сервером через SRV_CONTACT_PRES_INFO.
    /// </summary>
    public bool IsOnline { get; set; }

    /// <summary>
    /// Текущий статус присутствия контакта. Соответствует значениям PresStatus*.
    /// Например: PresStatusOnline(0x0000), PresStatusAway(0x0007).
    /// </summary>
    public uint PresenceStatus { get; set; }

    /// <summary>
    /// Текстовое описание статуса присутствия (status name).
    /// Определяется capability-дескриптором контакта.
    /// </summary>
    public string StatusName { get; set; } = string.Empty;

    /// <summary>
    /// Имя клиента контакта (client name/type). 
    /// Определяет тип приложения контакта: OBIMP-клиент, веб, HTTP и т.д.
    /// </summary>
    public string ClientName { get; set; } = string.Empty;

    /// <summary>
    /// MD5-хэш аватара контакта (8 байт). Получается через BEX 0x0006 (Avatars)
    /// или из SRV_OWN_AVATAR_HASH.
    /// </summary>
    public byte[]? AvatarMd5 { get; set; }

    /// <summary>
    /// Время подключения контакта (Connected Time). UTC.
    /// </summary>
    public DateTime ConnectedTime { get; set; }

    /// <summary>
    /// Пользовательские/разработческие sTLD элемента. 
    /// Ключ — тип sTLD (начинается с 0x8000), значение — данные.
    /// Ограничения: максимальное количество sTLD и максимальная длина определяются
    /// в SRV_PARAMS_REPLY (wTLD 0x0007 и wTLD 0x0008).
    /// </summary>
    public Dictionary<ulong, byte[]> CustomStlds { get; set; } = new();
}

// ========================================================================
// Сообщение чата (Chat Message)
// ========================================================================

/// <summary>
/// Сообщение в чате, полученное от контакта или отправленное.
/// Соответствует структуре SRV_MESSAGE / CLI_MESSAGE из BEX 0x0004.
/// </summary>
public class ChatMessage
{
    /// <summary>
    /// Имя аккаунта отправителя (SRV_MESSAGE, wTLD 0x0001).
    /// Для исходящих сообщений — имя аккаунта получателя (CLI_MESSAGE, wTLD 0x0001).
    /// </summary>
    public string SenderAccount { get; set; } = string.Empty;

    /// <summary>
    /// Уникальный идентификатор сообщения (wTLD 0x0002). Генерируется отправителем.
    /// Не должен быть нулём, иначе сервер закроет соединение.
    /// </summary>
    public uint MessageId { get; set; }

    /// <summary>
    /// Тип сообщения (wTLD 0x0003): MsgTypeUtf8(0x0001), MsgTypeRtf(0x0002), MsgTypeHtml(0x0003).
    /// Тип должен соответствовать capability удалённого клиента.
    /// </summary>
    public uint MessageType { get; set; }

    /// <summary>
    /// Текст сообщения (расшифрованный, если было зашифровано).
    /// Соответствует wTLD 0x0004 (BLK) после расшифровки.
    /// </summary>
    public string Text { get; set; } = string.Empty;

    /// <summary>
    /// Время получения сообщения.
    /// Для офлайн-сообщений соответствует wTLD 0x0008 (DateTime offline message time).
    /// </summary>
    public DateTime ReceivedTime { get; set; }

    /// <summary>
    /// true — сообщение было офлайн (получено через IM_CLI_REQ_OFFLINE).
    /// Устанавливается при получении флага wTLD 0x0007 (offline message flag).
    /// </summary>
    public bool IsOffline { get; set; }

    /// <summary>
    /// true — системное сообщение.
    /// Устанавливается при получении флага wTLD 0x0009 (system message flag).
    /// Позиция popup определяется wTLD 0x000A: 0 — default, 1 — screen center.
    /// </summary>
    public bool IsSystemMessage { get; set; }
}

// ========================================================================
// Сессия чата (Chat Session)
// ========================================================================

/// <summary>
/// Сессия чата с контактом. Хранит историю сообщений и состояние уведомления о наборе текста.
/// </summary>
public class ChatSession
{
    /// <summary>
    /// Контакт, с которым ведётся чат.
    /// </summary>
    public Contact Contact { get; set; } = null!;

    /// <summary>
    /// История сообщений в сессии. Коллекция обновляется при получении новых сообщений
    /// и уведомлений о наборе текста (CLI/SRV_NOTIFY).
    /// </summary>
    public ObservableCollection<ChatMessage> Messages { get; set; } = new();

    /// <summary>
    /// true — контакт сейчас печатает. Устанавливается при получении уведомления
    /// NOTIF_TYPE_USER_TYPING с NOTIF_VALUE_USER_TYPING_START.
    /// false — контакт прекратил печатать (NOTIF_VALUE_USER_TYPING_FINISH).
    /// </summary>
    public bool IsTyping { get; set; }
}

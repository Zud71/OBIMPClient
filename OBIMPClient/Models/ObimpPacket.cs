using System.Text;

namespace OBIMPClient.Models;

// ========================================================================
// Заголовок OBIMP-пакета
// ========================================================================

/// <summary>
/// Заголовок OBIMP-пакета, 17 байт. Все многобайтовые числа в Big-Endian (Network Byte Order).
/// Формат: Magic(1) + Sequence(4) + BexType(2) + BexSubtype(2) + RequestId(4) + DataLength(4)
/// </summary>
public class ObimpHeader
{
    /// <summary>
    /// Магический байт начала пакета — всегда '#'(0x23). Используется для валидации начала данных.
    /// </summary>
    public byte Magic { get; set; }

    /// <summary>
    /// Порядковый номер пакета, увеличивается на 1 при каждой отправке. Используется сервером
    /// для контроля целостности сессии. При получении неверного sequence сервер отправляет BYE
    /// с кодом BYE_REASON_INCORRECT_SEQ (0x0004).
    /// </summary>
    public uint Sequence { get; set; }

    /// <summary>
    /// Тип BEX-расширения (Broadcast Extension). Определяет область протокола.
    /// Значения: BexCommon(0x0001), BexContactList(0x0002), BexPresence(0x0003),
    /// BexIm(0x0004), BexUsersDirectory(0x0005), BexAvatars(0x0006),
    /// BexFileTransfer(0x0007), BexTransports(0x0008).
    /// </summary>
    public ushort BexType { get; set; }

    /// <summary>
    /// Подтип BEX-расширения. Определяет конкретное действие в рамках типа BEX.
    /// Например для BexCommon(0x0001): CliHello(0x0001), SrvHello(0x0002),
    /// CliLogin(0x0003), SrvLoginReply(0x0004), SrvBye(0x0005), KeepalivePing(0x0006),
    /// KeepalivePong(0x0007), CliRegister(0x0008), SrvRegisterReply(0x0009).
    /// </summary>
    public ushort BexSubtype { get; set; }

    /// <summary>
    /// Идентификатор запроса. Клиент генерирует уникальный RequestId для каждого запроса,
    /// сервер возвращает его в ответе для связывания запрос-ответ.
    /// </summary>
    public uint RequestId { get; set; }

    /// <summary>
    /// Длина данных пакета в байтах (без заголовка). Определяет количество байт wTLD после заголовка.
    /// Максимальная длина определяется сервером в SRV_LOGIN_REPLY (wTLD 0x0003).
    /// </summary>
    public uint DataLength { get; set; }

    /// <summary>
    /// Общий размер пакета в байтах (заголовок + данные).
    /// </summary>
    public int TotalLength => ObimpConstants.HeaderSize + (int)DataLength;

    /// <summary>
    /// Размер заголовка пакета — 17 байт (Magic:1 + Sequence:4 + BexType:2 + BexSubtype:2 + RequestId:4 + DataLength:4).
    /// </summary>
    public const int HeaderSize = 17;
}

// ========================================================================
// OBIMP-пакет
// ========================================================================

/// <summary>
/// Полный OBIMP-пакет, состоящий из заголовка и данных.
/// Данные представлены как байтовый массив (Data) и распарсенный список wTLD (Wtlds).
/// </summary>
public class ObimpPacket
{
    /// <summary>
    /// Заголовок пакета. Содержит тип BEX, подтип, порядковый номер, идентификатор запроса и длину данных.
    /// </summary>
    public ObimpHeader Header { get; set; } = new();

    /// <summary>
    /// Сырые данные пакета — байтовый массив, содержащий последовательность wTLD.
    /// </summary>
    public byte[] Data { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Распарсенный список wTLD (word-type, length, data) из данных пакета.
    /// Каждый wTLD состоит из: Type(2 байта) + Length(2 байта) + Data(n байт).
    /// </summary>
    public List<ObimpWtld> Wtlds { get; set; } = new();
}

// ========================================================================
// wTLD (word-type, length, data) — ключ данных уровня пакета
// ========================================================================

/// <summary>
/// wTLD (word-type, length, data) — основной элемент данных в OBIMP-пакете.
/// Используется во всех BEX-сообщениях на уровне пакета.
/// Структура: Type (Word, 2 байта) + Length (Word, 2 байта) + Data (Length байт).
/// 
/// Примеры использования:
///   - BEX COM: wTLD 0x0001 — имя аккаунта (UTF8), wTLD 0x0002 — ключ MD5 (BLK)
///   - BEX CL:  wTLD 0x0001 — ID элемента (LongWord), wTLD 0x0003 — sTLD массив
///   - BEX IM:  wTLD 0x0002 — уникальный ID сообщения (LongWord)
///   - BEX PRES: wTLD 0x0001 — значение статуса присутствия (LongWord)
/// </summary>
public class ObimpWtld
{
    /// <summary>
    /// Тип wTLD. Определяет назначение данных. Типы уникальны в пределах одного BEX-сообщения.
    /// Примеры: 0x0001 — имя аккаунта, 0x0002 — длина/данные, 0x0003 — тип сообщения.
    /// </summary>
    public uint Type { get; set; }

    /// <summary>
    /// Данные wTLD. Размер определяется полем Length в структуре wTLD.
    /// Содержимое зависит от типа: UTF8-строка, BLK-блок, LongWord, Word, OctaWord и т.д.
    /// </summary>
    public byte[] Data { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Фактическая длина данных в байтах.
    /// </summary>
    public int Length => Data.Length;

    /// <summary>
    /// Представление данных как UTF-8 строка. Используется для wTLD типа UTF8.
    /// Например: имя аккаунта, текст сообщения, URL, описание.
    /// </summary>
    public string AsUtf8() => Encoding.UTF8.GetString(Data);
}

// ========================================================================
// sTLD (sub-type, length, data) — ключ данных уровня элемента
// ========================================================================

/// <summary>
/// sTLD (sub-type, length, data) — элемент данных внутри элемента списка контактов.
/// Используется в BEX Contact List для хранения информации об элементе.
/// Структура: Type (Word, 2 байта) + Length (Word, 2 байта) + Data(n байт).
/// 
/// Примеры для элемента «Контакт» (CL_ITEM_TYPE_CONTACT):
///   sTLD 0x0002 — имя аккаунта (UTF8)
///   sTLD 0x0003 — отображаемое имя контакта (UTF8)
///   sTLD 0x0004 — тип приватности (Byte: 0x00-0x04)
///   sTLD 0x0005 — флаг авторизации (пустой)
///   sTLD 0x0006 — флаг общего элемента (пустой)
///   sTLD 0x1001 — ID транспорта (LongWord)
/// 
/// Примеры для элемента «Группа» (CL_ITEM_TYPE_GROUP):
///   sTLD 0x0001 — имя группы (UTF8)
/// 
/// Примеры для элемента «Заметка» (CL_ITEM_TYPE_NOTE):
///   sTLD 0x2001 — имя заметки (UTF8)
///   sTLD 0x2002 — тип заметки (Byte: текст/команда/ссылка/email/телефон)
///   sTLD 0x2003 — текст заметки (UTF8)
///   sTLD 0x2004 — дата создания (DateTime, UTC)
///   sTLD 0x2005 — MD5-хэш картинки (OctaWord, 8 байт)
/// 
/// Пользовательские/разработческие sTLD начинаются с 0x8000.
/// </summary>
public class ObimpStld
{
    /// <summary>
    /// Тип sTLD. Определяет назначение данных внутри элемента списка контактов.
    /// Стандартные типы: 0x0001-0x2005. Пользовательские: 0x8000+.
    /// </summary>
    public ushort Type { get; set; }

    /// <summary>
    /// Данные sTLD. Размер и формат зависят от типа.
    /// </summary>
    public byte[] Data { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Фактическая длина данных в байтах.
    /// </summary>
    public int Length => Data.Length;

    /// <summary>
    /// Представление данных как UTF-8 строка. Используется для sTLD с текстовыми значениями
    /// (имя аккаунта, имя группы, текст заметки, URL и т.д.).
    /// </summary>
    public string AsUtf8() => Encoding.UTF8.GetString(Data);
}

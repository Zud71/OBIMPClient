using OBIMPClient.Models;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Runtime.InteropServices;
using System.Text;

namespace OBIMPClient.Network;

// ========================================================================
// Serializer — сериализация/десериализация OBIMP-пакетов
// ========================================================================

/// <summary>
/// Статический класс для сериализации и десериализации OBIMP-пакетов.
/// Все многобайтовые числа записываются в Big-Endian (Network Byte Order) порядке.
/// 
/// Форматы данных wTLD:
///   - UTF8: строка в кодировке UTF-8
///   - Word (2 байта): ushort в Big-Endian
///   - LongWord (4 байта): uint в Big-Endian
///   - QuadWord (8 байт): ulong в Big-Endian
///   - DateTime (8 байт): UNIX timestamp (Int64 в Big-Endian), отсчёт от 1970-01-01 UTC
///   - BLK: произвольный байтовый массив
///   - Empty: пустой массив (флаги без данных)
/// </summary>
public static class Serializer
{
    // ========================================================================
    // Заголовок пакета (Header)
    // ========================================================================

    /// <summary>
    /// Десериализует заголовок OBIMP-пакета из первых 17 байтов буфера.
    /// Формат: Magic(1) + Sequence(4) + BexType(2) + BexSubtype(2) + RequestId(4) + DataLength(4).
    /// </summary>
    /// <param name="buffer">Буфер с данными, содержащий минимум 17 байт.</param>
    /// <returns>Распаршенный ObimpHeader.</returns>
    public static ObimpHeader DeserializeHeader(byte[] buffer)
    {
        return new ObimpHeader
        {
            Magic = buffer[0],
            Sequence = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(1)),
            BexType = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(5)),
            BexSubtype = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(7)),
            RequestId = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(9)),
            DataLength = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(13))
        };
    }

    /// <summary>
    /// Сериализует ObimpHeader в байтовый массив (17 байт).
    /// </summary>
    /// <param name="h">Заголовок для сериализации.</param>
    /// <returns>Байтовый массив размера 17.</returns>
    public static byte[] SerializeHeader(ObimpHeader h)
    {
        var buf = new byte[ObimpConstants.HeaderSize];
        buf[0] = h.Magic;
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(1), h.Sequence);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(5), h.BexType);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(7), h.BexSubtype);
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(9), h.RequestId);
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(13), h.DataLength);
        return buf;
    }

    // ========================================================================
    // wTLD (packet-level data keys)
    // ========================================================================

    /// <summary>
    /// Десериализует массив wTLD из байтового буфера.
    /// Каждый wTLD: Type(4 байта) + Length(4 байта) + Data(Length байт).
    /// Цикл продолжается, пока в буфере достаточно данных для чтения Type+Length.
    /// </summary>
    /// <param name="data">Буфер с данными wTLD.</param>
    /// <returns>Список распарсенных ObimpWtld.</returns>
    public static List<ObimpWtld> DeserializeWtlds(byte[] data)
    {
        var result = new List<ObimpWtld>();
        int pos = 0;
        while (pos + 8 <= data.Length)
        {
            var type = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos));
            pos += 4;
            var length = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos));
            pos += 4;
            if (pos + length > data.Length) break;
            var d = new byte[length];
            Array.Copy(data, pos, d, 0, length);
            pos += (int)length;
            result.Add(new ObimpWtld { Type = type, Data = d });
        }
        return result;
    }

    /// <summary>
    /// Сериализует список wTLD в байтовый массив.
    /// Каждый wTLD записывается как: Type(4) + Length(4) + Data(n).
    /// </summary>
    /// <param name="wtlds">Список wTLD для сериализации.</param>
    /// <returns>Байтовый массив с сериализованными wTLD.</returns>
    public static byte[] SerializeWtlds(List<ObimpWtld> wtlds)
    {
        using var ms = new MemoryStream();
        foreach (var w in wtlds)
        {
            var typeBuf = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(typeBuf, w.Type);
            var lenBuf = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(lenBuf, (uint)w.Length);
            ms.Write(typeBuf);
            ms.Write(lenBuf);
            if (w.Data.Length > 0) ms.Write(w.Data);
        }
        return ms.ToArray();
    }

    // ========================================================================
    // Фабричные методы создания wTLD
    // ========================================================================

    /// <summary>
    /// Создаёт wTLD с UTF-8 строкой в качестве данных.
    /// Применяется для: имён аккаунтов, текстов сообщений, URL, имён групп, описаний.
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    /// <param name="v">UTF-8 строка.</param>
    public static ObimpWtld Utf8Wtld(uint t, string v) => new() { Type = t, Data = Encoding.UTF8.GetBytes(v) };

    /// <summary>
    /// Создаёт wTLD с произвольным байтовым массивом (BLK).
    /// Применяется для: серверного ключа MD5 (BLK), публичного ключа шифрования (BLK),
    /// массива Word-пар (для SRV_LOGIN_REPLY wTLD 0x0002), данных аватара (BLK).
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    /// <param name="v">Байтовый массив.</param>
    public static ObimpWtld ToBytesWtld(uint t, byte[] v) => new() { Type = t, Data = v };

    /// <summary>
    /// Создаёт пустой wTLD (флаг без данных).
    /// Применяется для: флагов «авторизация», «офлайн-сообщение», «системное сообщение»,
    /// «неmultiple сообщение», «последний результат поиска».
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    public static ObimpWtld EmptyWtld(uint t) => new() { Type = t, Data = Array.Empty<byte>() };

    /// <summary>
    /// Создаёт wTLD с LongWord (uint, 4 байта Big-Endian).
    /// Применяется для: ID элементов, ID сообщений, статусов присутствия, лимитов, флагов.
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    /// <param name="v">Значение uint.</param>
    public static ObimpWtld LwWtld(uint t, uint v) => new() { Type = t, Data = ToBytes(v, 4) };

    /// <summary>
    /// Создаёт wTLD с Word (ushort, 2 байта Big-Endian).
    /// Применяется для: кодов ошибок, кодов результатов, типов BEX, типов сообщений.
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    /// <param name="v">Значение ushort.</param>
    public static ObimpWtld WwWtld(uint t, ushort v) => new() { Type = t, Data = ToBytes(v, 2) };

    /// <summary>
    /// Создаёт wTLD с Byte (1 байт).
    /// Применяется для: типов приватности (0x00-0x04), типов заметок, пола, типов опций транспорта.
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    /// <param name="v">Значение byte.</param>
    public static ObimpWtld BwWtld(uint t, byte v) => new() { Type = t, Data = new[] { v } };

    /// <summary>
    /// Создаёт wTLD с QuadWord (ulong, 8 байт Big-Endian).
    /// Применяется для: Item ID, Group ID (Contact List), MD5-хэшей (OctaWord).
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    /// <param name="v">Значение ulong.</param>
    public static ObimpWtld QwWtld(uint t, ulong v)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(b, v);
        return new ObimpWtld { Type = t, Data = b };
    }

    /// <summary>
    /// Создаёт wTLD с DateTime (8 байт Big-Endian UNIX timestamp).
    /// DateTime конвертируется в UTC и затем в количество секунд с 1970-01-01.
    /// Применяется для: даты создания заметки (sTLD 0x2004), времени офлайн-сообщения (wTLD 0x0008).
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    /// <param name="v">Значение DateTime (преобразуется в UTC).</param>
    public static ObimpWtld DtwWtld(uint t, DateTime v)
    {
        var unix = (long)(v.ToUniversalTime() - new DateTime(1970,1,1)).TotalSeconds;
        var b = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(b, unix);
        return new ObimpWtld { Type = t, Data = b };
    }

    /// <summary>
    /// Создаёт wTLD с BLK-байтами (обёртка для BlkWtld).
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    /// <param name="d">Байтовый массив.</param>
    public static ObimpWtld BlkWtld(uint t, byte[] d) => new() { Type = t, Data = d };

    /// <summary>
    /// Создаёт wTLD с массивом Word (пары Word для SRV_LOGIN_REPLY wTLD 0x0002 — список BEX).
    /// Каждая пара: BexType(Word) + MaxSubtype(Word).
    /// Применяется в SRV_LOGIN_REPLY для указания поддерживаемых сервером BEX-типов.
    /// </summary>
    /// <param name="t">Тип wTLD.</param>
    /// <param name="d">Массив ushort — пары (BexType, MaxSubtype).</param>
    public static ObimpWtld BlkWtld(uint t, ushort[] d)
    {
        byte[] byteArray = new byte[d.Length * 2];
        for (int i = 0; i < d.Length; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(byteArray.AsSpan(i * 2, 2), d[i]);
        }
        return new ObimpWtld { Type = t, Data = byteArray };
    }

    // ========================================================================
    // Методы извлечения данных из списка wTLD
    // ========================================================================

    /// <summary>
    /// Извлекает LongWord (uint) из списка wTLD по типу.
    /// </summary>
    /// <param name="ws">Список wTLD.</param>
    /// <param name="t">Тип wTLD для поиска.</param>
    /// <returns>Значение uint или null, если wTLD не найден или недостаточно данных.</returns>
    public static uint? GetLongWord(List<ObimpWtld> ws, uint t)
    {
        var w = ws.FirstOrDefault(x => x.Type == t);
        return w?.Data.Length >= 4 ? BinaryPrimitives.ReadUInt32BigEndian(w.Data) : null;
    }

    /// <summary>
    /// Извлекает Word (ushort) из списка wTLD по типу.
    /// </summary>
    /// <param name="ws">Список wTLD.</param>
    /// <param name="t">Тип wTLD для поиска.</param>
    /// <returns>Значение ushort или null.</returns>
    public static ushort? GetWord(List<ObimpWtld> ws, uint t)
    {
        var w = ws.FirstOrDefault(x => x.Type == t);
        return w?.Data.Length >= 2 ? BinaryPrimitives.ReadUInt16BigEndian(w.Data) : null;
    }

    /// <summary>
    /// Извлекает UTF-8 строку из списка wTLD по типу.
    /// </summary>
    /// <param name="ws">Список wTLD.</param>
    /// <param name="t">Тип wTLD для поиска.</param>
    /// <returns>UTF-8 строка или null.</returns>
    public static string? GetString(List<ObimpWtld> ws, uint t)
    {
        var w = ws.FirstOrDefault(x => x.Type == t);
        return w?.Data.Length > 0 ? w.AsUtf8() : null;
    }

    /// <summary>
    /// Извлекает DateTime из списка wTLD по типу.
    /// Данные интерпретируются как UNIX timestamp (Int64 Big-Endian).
    /// </summary>
    /// <param name="ws">Список wTLD.</param>
    /// <param name="t">Тип wTLD для поиска.</param>
    /// <returns>DateTime (UTC) или null.</returns>
    public static DateTime? GetDateTime(List<ObimpWtld> ws, uint t)
    {
        var w = ws.FirstOrDefault(x => x.Type == t);
        return w?.Data.Length >= 8
            ? new DateTime(1970,1,1).AddSeconds(BinaryPrimitives.ReadInt64BigEndian(w.Data))
            : null;
    }

    // ========================================================================
    // Внутренние методы
    // ========================================================================

    /// <summary>Конвертирует ushort в массив байт указанного размера в Big-Endian.</summary>
    private static byte[] ToBytes(ushort v, int len)
    {
        var b = new byte[len];
        BinaryPrimitives.WriteUInt16BigEndian(b, v);
        return b;
    }

    /// <summary>Конвертирует uint в массив байт указанного размера в Big-Endian.</summary>
    private static byte[] ToBytes(uint v, int len)
    {
        var b = new byte[len];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return b;
    }
}

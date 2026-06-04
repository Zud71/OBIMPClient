using System.Buffers;
using OBIMPClient.Models;
using OBIMPClient.Network;

namespace OBIMPClient.Client;

/// <summary>
/// Управление presence и статусом пользователя.
/// Реализует установку статуса присутствия через BEX Presence (0x0003, subtype 0x0004).
/// </summary>
public partial class ObimpClient
{
    // ========================================================================
    // Словари соответствия: имя статуса ↔ код статуса
    // ========================================================================

    /// <summary>
    /// Маппинг строковых имён статусов в их числовые значения (LongWord).
    /// Ключи — допустимые имена, значения — константы PresStatus*.
    /// </summary>
    public static readonly Dictionary<string, uint> StatusCodes = new()
    {
        ["online"] = ObimpConstants.PresStatusOnline,
        ["invisible"] = ObimpConstants.PresStatusInvisible,
        ["free"] = ObimpConstants.PresStatusFreeForChat,
        ["away"] = ObimpConstants.PresStatusAway,
        ["busy"] = ObimpConstants.PresStatusOccupied,
        ["occupied"] = ObimpConstants.PresStatusOccupied,
        ["dnd"] = ObimpConstants.PresStatusDoNotDisturb,
        ["donotdisturb"] = ObimpConstants.PresStatusDoNotDisturb,
    };

    /// <summary>
    /// Обратный маппинг: числовой код статуса в текстовое описание.
    /// </summary>
    public static readonly Dictionary<uint, string> StatusNames = new()
    {
        [ObimpConstants.PresStatusOnline] = "Online",
        [ObimpConstants.PresStatusInvisible] = "Invisible",
        [ObimpConstants.PresStatusFreeForChat] = "Free for chat",
        [ObimpConstants.PresStatusAway] = "Away",
        [ObimpConstants.PresStatusOccupied] = "Occupied",
        [ObimpConstants.PresStatusDoNotDisturb] = "Do not disturb",
    };

    // ========================================================================
    // Установка статуса
    // ========================================================================

    /// <summary>
    /// Устанавливает статус присутствия по текстовому имени.
    /// Поддерживаемые имена: "online", "invisible", "free", "away", "busy", "occupied",
    /// "dnd", "donotdisturb". Имя сравнивается без учёта регистра.
    /// При неизвестном имени выводится сообщение и метод завершается без отправки пакета.
    /// </summary>
    /// <param name="statusName">Текстовое имя статуса (case-insensitive).</param>
    public void SetStatus(string statusName)
    {
        if (!StatusCodes.TryGetValue(statusName.ToLowerInvariant(), out var code))
        {
            StatusMessage?.Invoke($"Unknown status: {statusName}");
            return;
        }
        SetPresenceStatus(code);
        StatusMessage?.Invoke($"Status changed to: {StatusNames.GetValueOrDefault(code, "Unknown")}");
    }

    /// <summary>
    /// Устанавливает статус присутствия напрямую по числовому коду.
    /// Использует константы PresStatus*: Online(0x0000), Invisible(0x0001),
    /// FreeForChat(0x0003), Away(0x0007), Occupied(0x0009), DoNotDisturb(0x000A).
    /// </summary>
    /// <param name="code">Числовой код статуса (LongWord).</param>
    public void SetStatus(uint code)
    {
        SetPresenceStatus(code);
        StatusMessage?.Invoke($"Status changed to: {StatusNames.GetValueOrDefault(code, "Unknown")}");
    }

    /// <summary>
    /// Формирует и отправляет пакет PRES_CLI_SET_STATUS (BEX 0x0003, subtype 0x0004).
    /// Содержит один wTLD 0x0001 с LongWord-кодом статуса.
    /// </summary>
    /// <param name="status">Числовой код статуса.</param>
    private void SetPresenceStatus(uint status)
    {
        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexPresence,
                BexSubtype = ObimpConstants.BexPresCliSetStatus
            },
            Wtlds = new()
            {
                // Согласно спецификации, wTLD 0x0001 в CLI_SET_STATUS содержит значение статуса (LongWord).
                Serializer.LwWtld(ObimpConstants.WtldPresCliStatusValue, status)
            }
        };
        _net.SendRequest(pkt);
    }
}
using System;
using System.IO;
using System.Text;
using System.Buffers.Binary;
using OBIMPClient.Models;
using OBIMPClient.Network;

namespace OBIMPClient.Client;

/// <summary>
/// Реализация публичных методов клиента для работы с протокоolem OBIMP.
/// Каждый метод формирует OBIMP-пакет согласно спецификации и отправляет через NetworkManager.
/// </summary>
public partial class ObimpClient
{
    // ========================================================================
    // Инициализация сессии
    // ========================================================================

    /// <summary>
    /// Отправляет запрос параметров списка контактов (CL_CLI_PARAMS, BEX 0x0002 subtype 0x0001).
    /// Используется после успешной авторизации для получения лимитов и настроек списка контактов.
    /// </summary>
    public void RequestServerParams()
    {
        var clParams = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexContactList,
                BexSubtype = ObimpConstants.BexClCliParams
            }
        };
        _net.SendRequest(clParams);
    }

    /// <summary>
    /// Запрашивает полный список контактов с сервера (CL_CLI_REQUEST, BEX 0x0002 subtype 0x0003).
    /// Сервер отвечает SRV_REPLY (subtype 0x0004), содержащим BLK-массив элементов списка контактов.
    /// </summary>
    public void RequestContactList()
    {
        var req = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexContactList,
                BexSubtype = ObimpConstants.BexClCliRequest
            }
        };
        _net.SendRequest(req);
    }

    // ========================================================================
    // Presence (присутствие)
    // ========================================================================

    /// <summary>
    /// Выполняет полную активацию presence broadcast в три этапа:
    /// 1. PRES_CLI_SET_PRES_INFO — отправляет capabilities, тип клиента, описание.
    /// 2. PRES_CLI_SET_STATUS — устанавливает статус Online.
    /// 3. PRES_CLI_ACTIVATE — активирует broadcast для контактов.
    /// </summary>
    public void ActivatePresence()
    {
        // 1. Set capabilities and presence info
        var capPkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexPresence,
                BexSubtype = ObimpConstants.BexPresCliSetPresInfo // 0x0003
            },
            Wtlds = new()
        {
            Serializer.BlkWtld(ObimpConstants.WtldPresCliCapabilities, new ushort[] {
                ObimpConstants.CapMsgsUtf8,
                ObimpConstants.CapMsgsRtf,
                ObimpConstants.CapNotifsTyping,
                ObimpConstants.CapAvatars
            }),
            Serializer.WwWtld(ObimpConstants.WtldPresCliClientType, ObimpConstants.ClientTypeUser),
            Serializer.Utf8Wtld(ObimpConstants.WtldPresCliClientName, "OBIMP Console Client"),
            Serializer.QwWtld(ObimpConstants.WtldPresCliClientVersion, 0x000100000001L), // Version 1.0.0.1
            Serializer.WwWtld(ObimpConstants.WtldPresCliLanguageCode, (ushort)LanguageCode.Russian) // 0x0034 (52)
        }
        };
        _net.SendRequest(capPkt);

        // 2. Set status to online
        var statusPkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexPresence,
                BexSubtype = ObimpConstants.BexPresCliSetStatus // 0x0004
            },
            Wtlds = new()
        {
            Serializer.LwWtld(ObimpConstants.WtldPresCliStatusValue, ObimpConstants.PresStatusOnline)
        }
        };
        _net.SendRequest(statusPkt);

        // 3. Activate presence broadcast
        var activatePkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexPresence,
                BexSubtype = ObimpConstants.BexPresCliActivate // 0x0005
            }
        };
        _net.SendRequest(activatePkt);
        StatusMessage?.Invoke("Presence activated");
    }
    // ========================================================================
    // Отправка сообщений (BEX Instant Messaging)
    // ========================================================================

    /// <summary>
    /// Отправляет текстовое UTF-8 сообщение контакту (IM_CLI_MESSAGE, BEX 0x0004 subtype 0x0006).
    /// </summary>
    public void SendMessage(string targetAccount, string text)
    {
        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexIm,
                BexSubtype = ObimpConstants.BexImCliMessage // 0x0006
            },
            Wtlds = new()
        {
            Serializer.Utf8Wtld(ObimpConstants.WtldImReceiverAccount, targetAccount), // Было 0x0001
            Serializer.LwWtld(ObimpConstants.WtldImMessageId, (uint)_msgIdCounter++),
            Serializer.LwWtld(ObimpConstants.WtldImMessageType, ObimpConstants.MsgTypeUtf8),
            Serializer.BlkWtld(ObimpConstants.WtldImMessageData, Encoding.UTF8.GetBytes(text)),
            Serializer.EmptyWtld(ObimpConstants.WtldImReqDeliveryReport)
        }
        };
        _net.SendRequest(pkt);
        StatusMessage?.Invoke($"Sent to {targetAccount}: {text}");
    }

    /// <summary>
    /// Отправляет уведомление о наборе текста (IM_CLI_SRV_NOTIFY, BEX 0x0004 subtype 0x0009).
    /// </summary>

    public void SendTypingNotification(string targetAccount, bool isTyping)
    {
        var code = isTyping
            ? ObimpConstants.NotifValueUserTypingStart
            : ObimpConstants.NotifValueUserTypingFinish;

        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexIm,
                BexSubtype = ObimpConstants.BexImCliSrvNotify // 0x0009
            },
            Wtlds = new()
        {
            Serializer.Utf8Wtld(ObimpConstants.WtldImNotifyAccount, targetAccount), // Было 0x0001
            Serializer.LwWtld(ObimpConstants.WtldImNotifyType, ObimpConstants.NotifTypeUserTyping), // Было 0x0002
            Serializer.LwWtld(ObimpConstants.WtldImNotifyValue, code) // Было 0x0003
        }
        };
        _net.SendRequest(pkt);
    }

    // ========================================================================
    // Управление списком контактов (BEX Contact List)
    // ========================================================================

    /// <summary>
    /// Добавляет контакт в список контактов (CL_CLI_ADD_ITEM, BEX 0x0002 subtype 0x0007).
    /// </summary>
    public void AddContact(string accountName, string displayName, ulong groupId = 0)
    {
        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexContactList,
                BexSubtype = ObimpConstants.BexClCliAddItem
            },
            Wtlds = new()
            {
                Serializer.WwWtld(ObimpConstants.WtldClItemType, ObimpConstants.ClItemTypeContact),
                
                Serializer.QwWtld(ObimpConstants.WtldClParentGroupId, groupId), 
                
                Serializer.BlkWtld(ObimpConstants.WtldClItemStlds, CreateContactStlds(
                    accountName,
                    displayName,
                    ObimpConstants.ClPrivTypeVisibleList,
                    true))
            }
        };
        _net.SendRequest(pkt);
        StatusMessage?.Invoke($"Adding contact: {accountName}");
    }

    /// <summary>
    /// Создаёт sTLD-массив для контакта согласно спецификации.
    /// ИСПРАВЛЕНИЕ: В исходном коде запись privacy и auth flag нарушала формат sTLD (Type+Length+Data).
    /// Теперь сериализация строго соответствует спецификации.
    /// </summary>
    private byte[] CreateContactStlds(string account, string name, byte privacy, bool authorized)
    {
        using var ms = new MemoryStream();

        WriteStld(ms, ObimpConstants.StldClContactAccountName, account);

        WriteStld(ms, ObimpConstants.StldClContactDisplayName, name);

        // sTLD 0x0004: privacy type (byte)
        var typeBuf4 = new byte[2];
        var lenBuf4 = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(typeBuf4, ObimpConstants.StldClContactPrivacyType);
        BinaryPrimitives.WriteUInt16BigEndian(lenBuf4, 1); // Длина данных = 1 байт
        ms.Write(typeBuf4);
        ms.Write(lenBuf4);
        ms.WriteByte(privacy);

        // sTLD 0x0005: auth flag (пустой = true)
        if (authorized)
        {
            var typeBuf5 = new byte[2];
            var lenBuf5 = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(typeBuf5, ObimpConstants.StldClContactAuthFlag);
            BinaryPrimitives.WriteUInt16BigEndian(lenBuf5, 0); // Длина данных = 0 байт (empty sTLD)
            ms.Write(typeBuf5);
            ms.Write(lenBuf5);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Запрашивает авторизацию контакта (CL_CLI_SRV_AUTH_REQUEST, BEX 0x0002 subtype 0x000D).
    /// </summary>
    public void RequestAuthorization(string accountName, string reason = " ")
    {
        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexContactList,
                BexSubtype = ObimpConstants.BexClCliSrvAuthRequest
            },
            Wtlds = new()
            {
                Serializer.Utf8Wtld(ObimpConstants.WtldClAccountName, accountName), 
                
                Serializer.Utf8Wtld(ObimpConstants.WtldClAuthReason, reason)
            }
        };
        _net.SendRequest(pkt);
        StatusMessage?.Invoke("Auth request sent to: " + accountName);
    }

    /// <summary>
    /// Удаляет элемент из списка контактов (CL_CLI_DEL_ITEM, BEX 0x0002 subtype 0x0009).
    /// </summary>
    public void DeleteContact(ulong itemId)
    {
        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexContactList,
                BexSubtype = ObimpConstants.BexClCliDelItem
            },
            Wtlds = new()
            {
                Serializer.QwWtld(ObimpConstants.WtldClItemId, itemId)
            }
        };
        _net.SendRequest(pkt);
    }

    /// <summary>
    /// Добавляет группу в список контактов (CL_CLI_ADD_ITEM, BEX 0x0002 subtype 0x0007).
    /// </summary>
    public void AddGroup(string name, ulong parentGroupId = 0)
    {
        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexContactList,
                BexSubtype = ObimpConstants.BexClCliAddItem
            },
            Wtlds = new()
            {
                Serializer.WwWtld(ObimpConstants.WtldClItemType, ObimpConstants.ClItemTypeGroup),
                
                Serializer.QwWtld(ObimpConstants.WtldClParentGroupId, parentGroupId), 
                
                Serializer.BlkWtld(ObimpConstants.WtldClItemStlds, CreateGroupStlds(name))
            }
        };
        _net.SendRequest(pkt);
    }

    /// <summary>
    /// Сериализует sTLD-массив для группы.
    /// </summary>
    private byte[] CreateGroupStlds(string name)
    {
        var data = Encoding.UTF8.GetBytes(name);
        using var ms = new MemoryStream();

        var typeBuf = new byte[2];
        var lenBuf = new byte[2];

        BinaryPrimitives.WriteUInt16BigEndian(typeBuf, ObimpConstants.StldClGroupName);
        BinaryPrimitives.WriteUInt16BigEndian(lenBuf, (ushort)data.Length);

        ms.Write(typeBuf);
        ms.Write(lenBuf);
        ms.Write(data);

        return ms.ToArray();
    }

    /// <summary>
    /// Вспомогательный метод для записи sTLD в MemoryStream.
    /// Формат sTLD: Type (Word, 2 байта Big-Endian) + Length (Word, 2 байта Big-Endian) + Data.
    /// </summary>
    private static void WriteStld(MemoryStream ms, ushort type, string value)
    {
        var data = Encoding.UTF8.GetBytes(value);
        var typeBuf = new byte[2];
        var lenBuf = new byte[2];

        BinaryPrimitives.WriteUInt16BigEndian(typeBuf, type);
        BinaryPrimitives.WriteUInt16BigEndian(lenBuf, (ushort)data.Length);

        ms.Write(typeBuf);
        ms.Write(lenBuf);
        ms.Write(data);
    }

    // ========================================================================
    // Ответы на авторизацию (BEX Contact List — Auth)
    // ========================================================================

    /// <summary>
    /// Отправляет ответ на запрос авторизации (CL_CLI_SRV_AUTH_REPLY, BEX 0x0002 subtype 0x000E).
    /// </summary>
    public void RespondToAuthRequest(string accountName, bool grant)
    {
        var code = grant
            ? ObimpConstants.AuthReplyGranted
            : ObimpConstants.AuthReplyDenied;

        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexContactList,
                BexSubtype = ObimpConstants.BexClCliSrvAuthReply
            },
            Wtlds = new()
            {
                Serializer.Utf8Wtld(ObimpConstants.WtldClAccountName, accountName), 
                
                Serializer.WwWtld(ObimpConstants.WtldClAuthReplyCode, code)
            }
        };
        _net.SendRequest(pkt);
        StatusMessage?.Invoke(grant
            ? $"Auth GRANTED to '{accountName}'"
            : $"Auth DENIED for '{accountName}'");
    }

    /// <summary>
    /// Отзывает ранее выданную авторизацию (CL_CLI_SRV_AUTH_REVOKE, BEX 0x0002 subtype 0x000F).
    /// </summary>
    public void RevokeAuthorization(string accountName, string reason = " ")
    {
        var pkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexContactList,
                BexSubtype = ObimpConstants.BexClCliSrvAuthRevoke
            },
            Wtlds = new()
            {
                Serializer.Utf8Wtld(ObimpConstants.WtldClAccountName, accountName), 
                
                Serializer.Utf8Wtld(ObimpConstants.WtldClAuthReason, reason)
            }
        };
        _net.SendRequest(pkt);
        StatusMessage?.Invoke($"Auth revoked for '{accountName}': {reason}");
    }
}
using OBIMPClient.Models;
using OBIMPClient.Network;
using OBIMPClient.Security;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace OBIMPClient.Client;

/// <summary>
/// Обработка входящих пакетов от сервера.
/// Диспетчеризует пакеты по BexType → BexSubtype и вызывает соответствующие обработчики.
/// </summary>
public partial class ObimpClient
{
    /// <summary>
    /// Главный метод обработки входящих пакетов от сервера.
    /// Вызывается NetworkManager при получении каждого пакета.
    /// Диспетризация по BexType (COM/CL/PRES/IM) → BexSubtype.
    /// </summary>
    /// <param name="pkt">Полученный OBIMP-пакет с распарсенным заголовком и wTLD.</param>
    private void OnPacketReceived(ObimpPacket pkt)
    {
        try
        {
            var wtlds = string.Join(", ", pkt.Wtlds?.Select(w => $"{w.Type}:0x{w.Type:X4}({w.Data.Length})") ?? Array.Empty<string>());
            Debug.WriteLine($"[INCOMING] BexType=0x{pkt.Header.BexType:X4} Subtype=0x{pkt.Header.BexSubtype:X4} DataLen={pkt.Header.DataLength} wTLDs=[{wtlds}]");

            switch (pkt.Header.BexType)
            {
                case ObimpConstants.BexCommon:
                    HandleCommonPacket(pkt);
                    break;
                case ObimpConstants.BexContactList:
                    HandleContactListPacket(pkt);
                    break;
                case ObimpConstants.BexPresence:
                    HandlePresencePacket(pkt);
                    break;
                case ObimpConstants.BexIm:
                    HandleImPacket(pkt);
                    break;
                default:
                    Debug.WriteLine($"[INCOMING] Unknown BexType=0x{pkt.Header.BexType:X4}, ignoring");
                    break;
            }
        }
        catch (Exception ex)
        {
            StatusMessage?.Invoke($"Packet handler error: {ex.Message}");
        }
    }

    // ========================================================================
    // BEX COM (Common) — авторизация, регистрация
    // ========================================================================

    /// <summary>
    /// Обрабатывает пакеты BEX Common (0x0001): SRV_LOGIN_REPLY, и другие.
    /// </summary>
    private async Task HandleCommonPacket(ObimpPacket pkt)
    {
        switch (pkt.Header.BexSubtype)
        {
            // SRV_LOGIN_REPLY — ответ сервера на попытку входа
            case ObimpConstants.BexComSrvLoginReply:
                HandleLoginReply(pkt);
                break;

            case ObimpConstants.BexComSrvHello:
                WaitForServerHello(pkt);
                break;
        }
    }

    /// <summary>
    /// Обрабатывает ответ сервера HELLO (первый пакет после подключения).
    /// Проверяет наличие ошибки входа, необходимость регистрации,
    /// извлекает серверный ключ и отправляет ответный пакет LOGIN с хешем пароля.
    /// </summary>
    /// <param name="pkt">Входящий пакет OBIMP от сервера.</param>
    private void WaitForServerHello(ObimpPacket pkt)
    {
        // Проверка корректности входного пакета
        if (pkt?.Header == null)
        {
            StatusMessage?.Invoke("Неверный пакет: отсутствует заголовок");
            return;
        }

        var wtlds = pkt.Wtlds;
        if (wtlds == null)
        {
            StatusMessage?.Invoke("Неверный пакет: отсутствует коллекция WTLD");
            return;
        }

        // 1. Проверяем наличие ошибки логина
        var errorWtld = wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldComLoginError);
        if (errorWtld != null)
        {
            GetLoginErrorCodeName(errorWtld);
            return;
        }

        if (string.IsNullOrEmpty(_myAccount) || string.IsNullOrEmpty(_myPassword))
        {
            StatusMessage?.Invoke("Ошибка");
            return;
        }

        // 2. Требуется ли регистрация?
        if (wtlds.Any(w => w.Type == ObimpConstants.WtldComRegistrationEnabled))
        {
            StatusMessage?.Invoke("Требуется регистрация через веб-страницу");
            return;
        }

        // 3. Получаем серверный ключ
        var serverKeyWtld = wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldComServerKey);
        if (serverKeyWtld == null || serverKeyWtld.Length < ObimpConstants.MinServerKeyLength)
        {
            StatusMessage?.Invoke("Ошибка: отсутствует или некорректен серверный ключ");
            return;
        }

        _serverKey = serverKeyWtld.Data;

        // 4. Генерируем хеш пароля и отправляем пакет LOGIN
        byte[] hash = PasswordHasher.GenerateHash(_myAccount, _myPassword, _serverKey);

        var loginPkt = new ObimpPacket
        {
            Header = new ObimpHeader
            {
                Magic = ObimpConstants.HeaderMagic,
                BexType = ObimpConstants.BexCommon,
                BexSubtype = ObimpConstants.BexComCliLogin
            },
            Wtlds = new()
        {
            Serializer.Utf8Wtld(ObimpConstants.WtldComCliAccountName, _myAccount),
            Serializer.ToBytesWtld(ObimpConstants.WtldComCliLoginMd5Hash, hash)
        }
        };

        _net.SendRequest(loginPkt);
    }

    /// <summary>
    /// Обрабатывает SRV_LOGIN_REPLY (BEX COM, подтип BexComSrvLoginReply).
    /// 
    /// Успех: нет wTLD WtldComLoginError (ошибки), есть wTLD WtldComSupportedBexs (поддерживаемые BEX),
    ///        wTLD WtldComMaxBexDataLen (макс. длина).
    /// Ошибка: есть wTLD WtldComLoginError с кодом ошибки.
    /// 
    /// Коды ошибок: LoginErrorAccountInvalid, LoginErrorServiceTempUnavailable,
    /// LoginErrorAccountBanned, LoginErrorWrongPassword, LoginErrorInvalidLogin.
    /// </summary>
    private void HandleLoginReply(ObimpPacket pkt)
    {
        // wTLD 0x0001 — код ошибки входа (если присутствует, значит вход не удался)
        var errorWtld = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldComLoginError);

        // wTLD 0x0002 — массив поддерживаемых сервером BEX (при успешном входе)
        var supportedBexWtld = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldComSupportedBexs);


        if (errorWtld == null && supportedBexWtld != null)
        {
            IsLoggedIn = true;
            StatusMessage?.Invoke($"Logged in as {_myAccount}");
            ParseServerSupportedBex(supportedBexWtld.Data);

            // wTLD 0x0003 — максимальная длина данных клиентского BEX
            var maxDataLenWtld = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldComMaxBexDataLen);
            if (maxDataLenWtld?.Data.Length >= 4)
            {
                var maxLen = BinaryPrimitives.ReadUInt32BigEndian(maxDataLenWtld.Data);
                StatusMessage?.Invoke($"Max BEX data length: {maxLen} bytes");
            }
            RequestServerParams();
        }
        else if (errorWtld != null)
        {
            GetLoginErrorCodeName(errorWtld);
        }
    }

    /// <summary>
    /// Парсит массив поддерживаемых сервером BEX из wTLD WtldComSupportedBexs в SRV_LOGIN_REPLY.
    /// Формат: последовательность пар Word (BEX type, max subtype).
    /// Каждая пара занимает 4 байта: BexType(2) + MaxSubtype(2).
    /// </summary>
    private void ParseServerSupportedBex(byte[] data)
    {
        var bexCount = data.Length / 4;
        for (int i = 0; i < bexCount; i++)
        {
            var bexType = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(i * 4));
            var maxSubtype = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(i * 4 + 2));
            StatusMessage?.Invoke($"Server supports BEX 0x{bexType:X4} (max subtype 0x{maxSubtype:X4})");
        }
    }

    /// <summary>
    /// Возвращает текстовое описание кода ошибки логина.
    /// Все коды соответствуют спецификации OBIMP (LOGIN_ERROR_CODE).
    /// </summary>
    private string GetLoginErrorCodeName(ObimpWtld errorWtld)
    {
        uint code = errorWtld.Data.Length >= 2
            ? BinaryPrimitives.ReadUInt16BigEndian(errorWtld.Data)
             : (uint)0;
        string errorMsg = "";

        IsLoggedIn = false;

        switch (code)
        {
            case ObimpConstants.LoginErrorAccountInvalid:
                errorMsg = "ACCOUNT_INVALID";
                break;
            case ObimpConstants.LoginErrorServiceTempUnavailable:
                errorMsg = "SERVICE_TEMP_UNAVAILABLE";
                break;
            case ObimpConstants.LoginErrorAccountBanned:
                errorMsg = "ACCOUNT_BANNED";
                break;
            case ObimpConstants.LoginErrorWrongPassword:
                errorMsg = "WRONG_PASSWORD";
                break;
            case ObimpConstants.LoginErrorInvalidLogin:
                errorMsg = "INVALID_LOGIN";
                break;
            default:
                errorMsg = "UNKNOWN";
                break;

        }

        StatusMessage?.Invoke($"Login failed: {code} ({errorMsg})");
        return errorMsg;
    }

    // ========================================================================
    // BEX CL (Contact List) — список контактов
    // ========================================================================

    /// <summary>
    /// Обрабатывает пакеты BEX Contact List (0x0002):
    /// SRV_PARAMS_REPLY, SRV_REPLY, SRV_VERIFY_REPLY,
    /// CLI_SRV_AUTH_REQUEST, CLI_SRV_AUTH_REPLY, CLI_SRV_AUTH_REVOKE, SRV_ITEM_OPER.
    /// </summary>
    private void HandleContactListPacket(ObimpPacket pkt)
    {
        switch (pkt.Header.BexSubtype)
        {
            // SRV_PARAMS_REPLY — параметры и лимиты списка контактов
            case ObimpConstants.BexClSrvParamsReply:
                HandleContactListParams(pkt);
                break;

            // SRV_REPLY — полный список контактов (BLK blob)
            case ObimpConstants.BexClSrvReply:
                ParseContactList(pkt);
                break;

            // SRV_VERIFY_REPLY — MD5-хэш серверного списка контактов
            case ObimpConstants.BexClSrvVerifyReply:
                StatusMessage?.Invoke($"Contact list MD5: {BitConverter.ToString(pkt.Data).Replace("-", "")}");
                break;

            // CLI/SRV_AUTH_REQUEST — входящий запрос авторизации
            case ObimpConstants.BexClCliSrvAuthRequest:
                HandleAuthRequest(pkt);
                break;

            // CLI/SRV_AUTH_REPLY — ответ на запрос авторизации (Granted/Denied)
            case ObimpConstants.BexClCliSrvAuthReply:
                HandleAuthReply(pkt);
                break;

            // CLI/SRV_AUTH_REVOKE — отзыв ранее выданной авторизации
            case ObimpConstants.BexClCliSrvAuthRevoke:
                HandleAuthRevoke(pkt);
                break;

            // SRV_ITEM_OPER — серверное уведомление об изменении элемента (ADD/DEL/UPD)
            case ObimpConstants.BexClSrvItemOper:
                HandleContactListItemOp(pkt);
                break;
        }
    }

    /// <summary>
    /// Обрабатывает SRV_PARAMS_REPLY (подтип BexClSrvParamsReply).
    /// wTLD WtldClMaxGroupsCount — макс. количество групп,
    /// wTLD WtldClMaxContactsCount — макс. контактов.
    /// </summary>
    private void HandleContactListParams(ObimpPacket pkt)
    {
        var maxGroups = Serializer.GetLongWord(pkt.Wtlds, ObimpConstants.WtldClMaxGroupsCount) ?? 0;
        var maxContacts = Serializer.GetLongWord(pkt.Wtlds, ObimpConstants.WtldClMaxContactsCount) ?? 0;
        StatusMessage?.Invoke($"CL params: groups={maxGroups}, contacts={maxContacts}");
    }

    /// <summary>
    /// Парсит полный список контактов из SRV_REPLY (подтип BexClSrvReply).
    /// Данные находятся в wTLD WtldClContactListData (BLK blob):
    ///   uint itemsCount(4) + [itemType(2) + itemId(4) + groupId(4) + stldLen(4) + stldData(stldLen)]*N
    /// </summary>
    private void ParseContactList(ObimpPacket pkt)
    {
        // wTLD 0x0001 — данные списка контактов (BLK blob)
        var w = pkt.Wtlds.FirstOrDefault(x => x.Type == ObimpConstants.WtldClContactListData);
        if (w == null || w.Data.Length < 4) return;

        var itemsCount = BinaryPrimitives.ReadUInt32BigEndian(w.Data);
        int pos = 4;
        _contacts.Clear();

        for (int i = 0; i < itemsCount && pos < w.Data.Length; i++)
        {
            if (pos + 14 > w.Data.Length) break;

            var itemType = BinaryPrimitives.ReadUInt16BigEndian(w.Data.AsSpan(pos)); pos += 2;
            var itemId = BinaryPrimitives.ReadUInt32BigEndian(w.Data.AsSpan(pos)); pos += 4;
            var groupId = BinaryPrimitives.ReadUInt32BigEndian(w.Data.AsSpan(pos)); pos += 4;

            var contact = new Contact
            {
                ItemId = itemId,
                GroupId = groupId,
                // Приводим к enum ContactItemType (Group=1, Contact=2, Transport=3, Note=4)
                ItemType = (ContactItemType)itemType
            };

            var stldLen = BinaryPrimitives.ReadUInt32BigEndian(w.Data.AsSpan(pos)); pos += 4;
            if ((int)stldLen >= 0 && (pos + (int)stldLen) <= w.Data.Length)
            {
                var stldData = new byte[stldLen];
                Array.Copy(w.Data, pos, stldData, 0, stldLen);
                pos += (int)stldLen;
                ParseContactStlds(contact, stldData);
            }
            _contacts[itemId] = contact;
        }
        UpdateContactDisplayNames();
        StatusMessage?.Invoke($"Contact list loaded: {_contacts.Count} items");
    }

    /// <summary>
    /// Парсит sTLD-массив элемента списка контактов.
    /// Для контакта (ContactItemType.Contact):
    ///   StldClContactAccountName, StldClContactDisplayName, StldClContactPrivacyType,
    ///   StldClContactAuthFlag, StldClContactGeneralFlag.
    /// Для группы (ContactItemType.Group):
    ///   StldClGroupName.
    /// </summary>
    private void ParseContactStlds(Contact contact, byte[] stldData)
    {
        int pos = 0;
        while (pos + 4 <= stldData.Length)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(stldData.AsSpan(pos)); pos += 2;
            var len = BinaryPrimitives.ReadUInt16BigEndian(stldData.AsSpan(pos)); pos += 2;
            if (pos + len > stldData.Length) break;

            if (contact.ItemType == ContactItemType.Contact)
            {
                switch (type)
                {
                    // sTLD 0x0002 — имя аккаунта контакта (UTF8)
                    case ObimpConstants.StldClContactAccountName:
                        contact.AccountName = Encoding.UTF8.GetString(stldData, pos, len);
                        break;

                    // sTLD 0x0003 — отображаемое имя контакта (UTF8)
                    case ObimpConstants.StldClContactDisplayName:
                        contact.DisplayName = Encoding.UTF8.GetString(stldData, pos, len);
                        break;

                    // sTLD 0x0004 — тип приватности (Byte: 0x00..0x04)
                    case ObimpConstants.StldClContactPrivacyType:
                        contact.PrivacyType = (ContactPrivacyType)stldData[pos];
                        break;

                    // sTLD 0x0005 — флаг авторизации (пустой sTLD, наличие означает true)
                    case ObimpConstants.StldClContactAuthFlag:
                        contact.IsAuthorized = len > 0;
                        break;

                    // sTLD 0x0006 — флаг общего (системного) элемента (пустой sTLD)
                    case ObimpConstants.StldClContactGeneralFlag:
                        contact.IsGeneral = len > 0;
                        break;
                }
            }
            else if (contact.ItemType == ContactItemType.Group)
            {
                // sTLD 0x0001 — имя группы (UTF8)
                if (type == ObimpConstants.StldClGroupName)
                {
                    contact.DisplayName = Encoding.UTF8.GetString(stldData, pos, len);
                    _groupMap[contact.ItemId] = contact.DisplayName;
                }
            }
            pos += len;
        }
    }

    /// <summary>
    /// Заполняет пустые DisplayName именем аккаунта.
    /// </summary>
    private void UpdateContactDisplayNames()
    {
        foreach (var c in _contacts.Values)
            if (string.IsNullOrEmpty(c.DisplayName)) c.DisplayName = c.AccountName;
    }

    /// <summary>
    /// Обрабатывает SRV_ITEM_OPER (подтип BexClSrvItemOper).
    /// wTLD WtldClOperCode — код операции (OperAddItem, OperDelItem, OperUpdItem).
    /// wTLD WtldClOperItemId — Item ID элемента.
    /// </summary>
    private void HandleContactListItemOp(ObimpPacket pkt)
    {
        // wTLD 0x0001 — код серверной операции над элементом
        var opCode = Serializer.GetWord(pkt.Wtlds, ObimpConstants.WtldClOperCode) ?? 0;

        // wTLD 0x0003 — ID элемента, над которым производится операция
        var itemId = Serializer.GetLongWord(pkt.Wtlds, ObimpConstants.WtldClOperItemId) ?? 0;

        switch (opCode)
        {
            // 0x0001 — добавление элемента в список
            case ObimpConstants.OperAddItem:
                StatusMessage?.Invoke($"Contact item added: ID {itemId}");
                break;

            // 0x0002 — удаление элемента из списка
            case ObimpConstants.OperDelItem:
                _contacts.Remove(itemId);
                StatusMessage?.Invoke($"Contact item deleted: ID {itemId}");
                break;

            // 0x0003 — обновление данных элемента
            case ObimpConstants.OperUpdItem:
                StatusMessage?.Invoke($"Contact item updated: ID {itemId}");
                break;
        }
        ContactListUpdated?.Invoke("item_op", null!);
    }

    // ========================================================================
    // BEX PRESENCE (присутствие)
    // ========================================================================

    /// <summary>
    /// Обрабатывает пакеты BEX Presence (0x0003):
    /// SRV_CONTACT_ONLINE (подключение контакта), SRV_CONTACT_OFFLINE (отключение).
    /// </summary>
    private void HandlePresencePacket(ObimpPacket pkt)
    {
        switch (pkt.Header.BexSubtype)
        {
            // SRV_CONTACT_ONLINE — контакт перешёл в онлайн
            case ObimpConstants.BexPresSrvContactOnline:
                HandleContactOnline(pkt);
                break;

            // SRV_CONTACT_OFFLINE — контакт перешёл в оффлайн
            case ObimpConstants.BexPresSrvContactOffline:
                HandleContactOffline(pkt);
                break;
        }
    }

    /// <summary>
    /// Обрабатывает SRV_CONTACT_ONLINE (подтип BexPresSrvContactOnline).
    /// Извлекает из wTLD: имя аккаунта, статус, имя статуса, имя клиента,
    /// время подключения, MD5 аватара. Обновляет существующий контакт или создаёт новый.
    /// </summary>
    private void HandleContactOnline(ObimpPacket pkt)
    {
        // wTLD 0x0001 — имя аккаунта (UTF8)
        var acct = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldPresAccountName)?.AsUtf8() ?? "";

        // wTLD 0x0002 — значение статуса присутствия (LongWord, например PresStatusOnline)
        var status = Serializer.GetLongWord(pkt.Wtlds, ObimpConstants.WtldPresStatusValue) ?? 0;

        var contact = _contacts.Values.FirstOrDefault(c => c.AccountName == acct);

        if (contact != null)
        {
            contact.IsOnline = true;
            contact.PresenceStatus = status;

            // wTLD 0x0003 — название пользовательского статуса (UTF8)
            contact.StatusName = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldPresStatusName)?.AsUtf8() ?? "";

            // wTLD 0x0008 — название клиента (UTF8)
            contact.ClientName = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldPresClientName)?.AsUtf8() ?? "";

            // wTLD 0x000A — время подключения в текущей сессии (DateTime)
            contact.ConnectedTime = Serializer.GetDateTime(pkt.Wtlds, ObimpConstants.WtldPresConnectedTime) ?? DateTime.MinValue;

            // wTLD 0x000C — MD5-хэш аватара (OctaWord, 16 байт)
            var avatarHash = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldPresAvatarMd5)?.Data;
            if (avatarHash?.Length == 16) contact.AvatarMd5 = avatarHash;

            ContactPresenceChanged?.Invoke(contact, true, status, contact.StatusName);
        }
        else
        {
            var newContact = new Contact
            {
                AccountName = acct,
                DisplayName = acct,
                IsOnline = true,
                PresenceStatus = status,
                StatusName = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldPresStatusName)?.AsUtf8() ?? "",
                ClientName = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldPresClientName)?.AsUtf8() ?? ""
            };
            ContactPresenceChanged?.Invoke(newContact, true, status, newContact.StatusName);
        }
    }

    /// <summary>
    /// Обрабатывает SRV_CONTACT_OFFLINE (подтип BexPresSrvContactOffline).
    /// wTLD WtldPresAccountName — имя аккаунта. Устанавливает IsOnline = false.
    /// </summary>
    private void HandleContactOffline(ObimpPacket pkt)
    {
        // wTLD 0x0001 — имя аккаунта (UTF8)
        var acct = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldPresAccountName)?.AsUtf8() ?? "";

        var contact = _contacts.Values.FirstOrDefault(c => c.AccountName == acct);
        if (contact != null)
        {
            contact.IsOnline = false;
            ContactPresenceChanged?.Invoke(contact, false, 0, "");
        }
        else
        {
            // Резервный поиск на случай рассинхронизации
            foreach (var c in _contacts.Values)
                if (c.AccountName == acct) { c.IsOnline = false; break; }
        }
    }

    // ========================================================================
    // BEX IM (Instant Messaging) — сообщения
    // ========================================================================

    /// <summary>
    /// Обрабатывает пакеты BEX Instant Messaging (0x0004):
    /// SRV_MESSAGE (входящее сообщение), CLI_SRV_MSG_REPORT (отчёт о доставке).
    /// </summary>
    private void HandleImPacket(ObimpPacket pkt)
    {
        switch (pkt.Header.BexSubtype)
        {
            // SRV_MESSAGE — входящее сообщение от контакта
            case ObimpConstants.BexImSrvMessage:
                HandleReceivedMessage(pkt);
                break;

            // CLI/SRV_MSG_REPORT — подтверждение доставки сообщения
            case ObimpConstants.BexImCliSrvMsgReport:
                HandleMessageReport(pkt);
                break;
        }
    }

    /// <summary>
    /// Обрабатывает входящее сообщение IM_SRV_MESSAGE (подтип BexImSrvMessage).
    /// Извлекает: отправителя, ID сообщения, тип, данные, флаги офлайн и системного сообщения.
    /// </summary>
    private void HandleReceivedMessage(ObimpPacket pkt)
    {
        // wTLD 0x0001 — имя аккаунта отправителя (UTF8)
        var sender = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldImSenderAccount)?.AsUtf8() ?? "";

        // wTLD 0x0002 — уникальный ID сообщения (LongWord)
        var msgId = Serializer.GetLongWord(pkt.Wtlds, ObimpConstants.WtldImMessageId) ?? 0;

        // wTLD 0x0003 — тип сообщения (LongWord: MsgTypeUtf8, MsgTypeRtf, MsgTypeHtml)
        var msgType = Serializer.GetLongWord(pkt.Wtlds, ObimpConstants.WtldImMessageType) ?? 0;

        // wTLD 0x0007 — флаг офлайн-сообщения (пустой sTLD, наличие = true)
        var isOffline = pkt.Wtlds.Any(w => w.Type == ObimpConstants.WtldImOfflineFlag);

        // wTLD 0x0009 — флаг системного сообщения (пустой sTLD, наличие = true)
        var isSystem = pkt.Wtlds.Any(w => w.Type == ObimpConstants.WtldImSystemFlag);

        // Данные сообщения: wTLD 0x0004 (основные данные сообщения, BLK)
        var msgText = "";
        var dataWtld = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldImMessageData);
        if (dataWtld != null && dataWtld.Data.Length > 0)
        {
            msgText = Encoding.UTF8.GetString(dataWtld.Data);
        }
        else
        {
            // Альтернативно: wTLD 0x0006 (по спецификации это EncryptionType,
            // но в исходном коде использовался как альтернативное тело сообщения)
            var bodyWtld = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldImEncryptionType);
            if (bodyWtld != null && bodyWtld.Data.Length > 0)
                msgText = Encoding.UTF8.GetString(bodyWtld.Data);
        }

        var chatMsg = new ChatMessage
        {
            SenderAccount = sender,
            MessageId = (uint)msgId,
            MessageType = msgType,
            Text = msgText,
            ReceivedTime = DateTime.Now,
            IsOffline = isOffline,
            IsSystemMessage = isSystem
        };

        // Находим или создаём сессию чата
        var session = _chatSessions.FirstOrDefault(s => s.Contact.AccountName == sender);
        if (session == null)
        {
            var contact = _contacts.Values.FirstOrDefault(c => c.AccountName == sender);
            if (contact == null) contact = new Contact { AccountName = sender, DisplayName = sender };
            session = new ChatSession { Contact = contact };
            _chatSessions.Add(session);
        }
        session.Messages.Add(chatMsg);
        SessionChanged?.Invoke(session.Contact.AccountName, true);
        MessageReceived?.Invoke(sender, "message", chatMsg);
    }

    /// <summary>
    /// Обрабатывает отчёт о доставке сообщения IM_CLI_SRV_MSG_REPORT (подтип BexImCliSrvMsgReport).
    /// wTLD WtldImReportMessageId — ID сообщения, по которому пришёл отчёт.
    /// </summary>
    private void HandleMessageReport(ObimpPacket pkt)
    {
        // wTLD 0x0002 — уникальный ID сообщения, на которое пришёл отчёт (LongWord)
        var reportType = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldImReportMessageId)?.Data;
        if (reportType?.Length > 0)
            Debug.WriteLine($"Message report: type={reportType[0]}");
    }

    // ========================================================================
    // Обработчики авторизации
    // ========================================================================

    /// <summary>
    /// Обрабатывает входящий запрос авторизации CLI_SRV_AUTH_REQUEST (подтип BexClCliSrvAuthRequest).
    /// wTLD WtldClAccountName — отправитель (UTF8),
    /// wTLD WtldClAuthReason — причина (UTF8),
    /// wTLD WtldClOfflineFlag — офлайн-флаг (пустой),
    /// wTLD WtldClOfflineTime — время офлайн-сообщения (DateTime).
    /// </summary>
    private void HandleAuthRequest(ObimpPacket pkt)
    {
        // wTLD 0x0001 — имя аккаунта отправителя запроса (UTF8)
        var sender = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldClAccountName)?.AsUtf8() ?? "";

        // wTLD 0x0002 — причина запроса авторизации (UTF8)
        var reason = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldClAuthReason)?.AsUtf8() ?? "";

        // wTLD 0x0003 — флаг офлайн-сообщения авторизации (пустой)
        var isOffline = pkt.Wtlds.Any(w => w.Type == ObimpConstants.WtldClOfflineFlag);

        // wTLD 0x0004 — время офлайн-сообщения авторизации (DateTime)
        var offlineTime = Serializer.GetDateTime(pkt.Wtlds, ObimpConstants.WtldClOfflineTime) ?? DateTime.MinValue;

        var mode = isOffline ? "offline" : "online";
        if (isOffline)
            StatusMessage?.Invoke($"[AUTH] Offline auth request from '{sender}' at {offlineTime:yyyy-MM-dd HH:mm:ss}: {reason}");
        else
            StatusMessage?.Invoke($"[AUTH] Incoming authorization request from '{sender}': {reason}");

        AuthorizationRequestReceived?.Invoke(sender, reason, mode);
    }

    /// <summary>
    /// Обрабатывает ответ на запрос авторизации CLI_SRV_AUTH_REPLY (подтип BexClCliSrvAuthReply).
    /// wTLD WtldClAccountName — отправитель (UTF8),
    /// wTLD WtldClAuthReplyCode — код ответа (Word: AuthReplyCode.Granted / AuthReplyCode.Denied),
    /// wTLD WtldClOfflineFlag — офлайн-флаг,
    /// wTLD WtldClOfflineTime — время офлайн-сообщения.
    /// 
    /// При Granted автоматически устанавливает IsAuthorized = true для контакта.
    /// </summary>
    private void HandleAuthReply(ObimpPacket pkt)
    {
        // wTLD 0x0001 — имя аккаунта, ответившего на запрос авторизации (UTF8)
        var contactAccount = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldClAccountName)?.AsUtf8() ?? "";

        // wTLD 0x0002 — код ответа на запрос авторизации (Word)
        var codeBytes = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldClAuthReplyCode)?.Data;

        // wTLD 0x0003 — флаг офлайн-сообщения авторизации (пустой)
        var isOffline = pkt.Wtlds.Any(w => w.Type == ObimpConstants.WtldClOfflineFlag);

        AuthReplyCode code = 0;
        if (codeBytes != null && codeBytes.Length >= 2)
            code = (AuthReplyCode)BinaryPrimitives.ReadUInt16BigEndian(codeBytes);

        switch (code)
        {
            // 0x0001 — авторизация одобрена
            case AuthReplyCode.Granted:
                AuthorizationReplyReceived?.Invoke(contactAccount, true);
                StatusMessage?.Invoke($"[AUTH] Authorization granted by '{contactAccount}'");
                var contact = _contacts.Values.FirstOrDefault(c => c.AccountName == contactAccount);
                if (contact != null)
                {
                    contact.IsAuthorized = true;
                    StatusMessage?.Invoke($"[AUTH] Contact '{contactAccount}' is now authorized");
                }
                else
                    StatusMessage?.Invoke($"[AUTH] Contact '{contactAccount}' is authorized (not in local list yet)");
                break;

            // 0x0002 — авторизация отклонена
            case AuthReplyCode.Denied:
                AuthorizationReplyReceived?.Invoke(contactAccount, false);
                StatusMessage?.Invoke($"[AUTH] Authorization denied by '{contactAccount}'");
                break;

            default:
                StatusMessage?.Invoke($"[AUTH] Unknown auth reply from '{contactAccount}': {(ushort)code}");
                break;
        }

        if (isOffline)
        {
            // wTLD 0x0004 — время офлайн-сообщения авторизации (DateTime)
            var offlineTime = Serializer.GetDateTime(pkt.Wtlds, ObimpConstants.WtldClOfflineTime) ?? DateTime.MinValue;
            StatusMessage?.Invoke($"[AUTH] This was an offline message (received at {offlineTime:yyyy-MM-dd HH:mm:ss})");
        }
    }

    /// <summary>
    /// Обрабатывает отзыв авторизации CLI_SRV_AUTH_REVOKE (подтип BexClCliSrvAuthRevoke).
    /// wTLD WtldClAccountName — отправитель (UTF8),
    /// wTLD WtldClAuthReason — причина (UTF8),
    /// wTLD WtldClOfflineFlag — офлайн-флаг,
    /// wTLD WtldClOfflineTime — время офлайн-сообщения.
    /// Автоматически снимает IsAuthorized = false для контакта.
    /// </summary>
    private void HandleAuthRevoke(ObimpPacket pkt)
    {
        // wTLD 0x0001 — имя аккаунта, отозвавшего авторизацию (UTF8)
        var contactAccount = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldClAccountName)?.AsUtf8() ?? "";

        // wTLD 0x0002 — причина отзыва авторизации (UTF8)
        var reason = pkt.Wtlds.FirstOrDefault(w => w.Type == ObimpConstants.WtldClAuthReason)?.AsUtf8() ?? "";

        // wTLD 0x0003 — флаг офлайн-сообщения авторизации (пустой)
        var isOffline = pkt.Wtlds.Any(w => w.Type == ObimpConstants.WtldClOfflineFlag);

        // wTLD 0x0004 — время офлайн-сообщения авторизации (DateTime)
        var offlineTime = Serializer.GetDateTime(pkt.Wtlds, ObimpConstants.WtldClOfflineTime) ?? DateTime.MinValue;

        AuthorizationRevokedReceived?.Invoke(contactAccount, reason);
        StatusMessage?.Invoke($"[AUTH] Authorization revoked by '{contactAccount}': {reason}");

        var contact = _contacts.Values.FirstOrDefault(c => c.AccountName == contactAccount);
        if (contact != null)
        {
            contact.IsAuthorized = false;
            StatusMessage?.Invoke($"[AUTH] Contact '{contactAccount}' authorization flag removed");
        }
        else
            StatusMessage?.Invoke($"[AUTH] Contact '{contactAccount}' not found in local list");

        if (isOffline)
            StatusMessage?.Invoke($"[AUTH] This was an offline message (received at {offlineTime:yyyy-MM-dd HH:mm:ss})");
    }

}
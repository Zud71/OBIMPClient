using System;

namespace OBIMPClient.Models;

/// <summary>
/// Константы протокола OBIMP (Open Binary Instant Messaging Protocol).
/// Строго соответствуют спецификации OBIMP Draft 1.1 Rev C.
/// Каждая константа имеет комментарий, описывающий её назначение и тип данных.
/// </summary>
public static class ObimpConstants
{
    // ========================================================================
    // Глобальные настройки, порты и лимиты
    // ========================================================================

    /// <summary>Магический байт начала каждого пакета OBIMP — символ '#' (0x23).</summary>
    public const byte HeaderMagic = (byte)'#';

    /// <summary>Фиксированный размер заголовка пакета OBIMP в байтах (17 байт).</summary>
    public const int HeaderSize = 17;

    /// <summary>Порт по умолчанию для клиентских TCP-подключений к серверу OBIMP.</summary>
    public const int DefaultPort = 7023;

    /// <summary>Порт по умолчанию для административных TCP-подключений.</summary>
    public const int AdminPort = 7024;

    /// <summary>Порт по умолчанию для прямых/прокси подключений передачи файлов.</summary>
    public const int FileTransferPort = 7025;

    /// <summary>Порт по умолчанию для защищенных (TLS/SSL) клиентских TCP-подключений.</summary>
    public const int DefaultSecurePort = 7033;

    /// <summary>Порт по умолчанию для защищенных (TLS/SSL) административных подключений.</summary>
    public const int SecureAdminPort = 7034;

    /// <summary>Порт по умолчанию для защищенных (TLS/SSL) подключений передачи файлов.</summary>
    public const int SecureFileTransferPort = 7035;

    /// <summary>Максимальный размер данных BEX-пакета от клиента (по умолчанию 128 КБ). Превышение ведёт к разрыву соединения.</summary>
    public const uint ObimpBexMaxDataLen = 0x00020000;

    /// <summary>Максимальный размер блока данных файла (wTLD) при прямой/прокси передаче (2048 байт).</summary>
    public const uint ObimpMaxFileDataWtdlLen = 0x00000800;

    // <summary>
    /// Минимальная ожидаемая длина серверного ключа (Server Key) в байтах для генерации MD5-хэша.
    /// </summary>
    public const int MinServerKeyLength = 32;

    /// <summary>
    /// Таймаут ожидания ответа SRV_HELLO от сервера (в миллисекундах).
    /// </summary>
    public const int ServerHelloTimeoutMs = 5000;

    /// <summary>
    /// Таймаут ожидания ответа на запрос регистрации (в миллисекундах).
    /// </summary>
    public const int RegistrationTimeoutMs = 3000;

    /// <summary>
    /// Интервал опроса (polling) при ожидании асинхронных задач (в миллисекундах).
    /// </summary>
    public const int PollingIntervalMs = 100;

    // ========================================================================
    // BEX 0x0001 — Common (Общие: управление сессией, вход, регистрация)
    // ========================================================================

    /// <summary>Тип BEX: Common (0x0001) — базовое управление сессией.</summary>
    public const ushort BexCommon = 0x0001;
    /// <summary>Подтип: CLI_HELLO (0x0001) — клиент инициирует подключение, передавая имя аккаунта.</summary>
    public const ushort BexComCliHello = 0x0001;
    /// <summary>Подтип: SRV_HELLO (0x0002) — сервер отвечает ключом для MD5, кодом ошибки или перенаправлением.</summary>
    public const ushort BexComSrvHello = 0x0002;
    /// <summary>Подтип: CLI_LOGIN (0x0003) — клиент выполняет вход, передавая имя и MD5-хэш пароля.</summary>
    public const ushort BexComCliLogin = 0x0003;
    /// <summary>Подтип: SRV_LOGIN_REPLY (0x0004) — сервер подтверждает вход или возвращает ошибку.</summary>
    public const ushort BexComSrvLoginReply = 0x0004;
    /// <summary>Подтип: SRV_BYE (0x0005) — сервер принудительно закрывает соединение с указанием причины.</summary>
    public const ushort BexComSrvBye = 0x0005;
    /// <summary>Подтип: CLI/SRV_KEEPALIVE_PING (0x0006) — запрос проверки активности соединения.</summary>
    public const ushort BexComCliSrvKeepalivePing = 0x0006;
    /// <summary>Подтип: CLI/SRV_KEEPALIVE_PONG (0x0007) — ответ на запрос проверки активности.</summary>
    public const ushort BexComCliSrvKeepalivePong = 0x0007;
    /// <summary>Подтип: CLI_REGISTER (0x0008) — клиент пытается зарегистрировать новый аккаунт.</summary>
    public const ushort BexComCliRegister = 0x0008;
    /// <summary>Подтип: SRV_REGISTER_REPLY (0x0009) — сервер возвращает результат попытки регистрации.</summary>
    public const ushort BexComSrvRegisterReply = 0x0009;

    // --- Коды ошибок HELLO ---
    /// <summary>Ошибка HELLO: аккаунт не существует или невалиден.</summary>
    public const ushort HelloErrorAccountInvalid = 0x0001;
    /// <summary>Ошибка HELLO: сервис временно недоступен.</summary>
    public const ushort HelloErrorServiceTempUnavailable = 0x0002;
    /// <summary>Ошибка HELLO: аккаунт заблокирован (бан).</summary>
    public const ushort HelloErrorAccountBanned = 0x0003;
    /// <summary>Ошибка HELLO: переданный cookie сервера неверен или устарел.</summary>
    public const ushort HelloErrorWrongCookie = 0x0004;
    /// <summary>Ошибка HELLO: превышен лимит одновременных подключений.</summary>
    public const ushort HelloErrorTooManyClients = 0x0005;
    /// <summary>Ошибка HELLO: неверный формат или недопустимое имя для входа.</summary>
    public const ushort HelloErrorInvalidLogin = 0x0006;

    // --- Коды ошибок LOGIN ---
    /// <summary>Ошибка LOGIN: аккаунт не существует или невалиден.</summary>
    public const ushort LoginErrorAccountInvalid = 0x0001;
    /// <summary>Ошибка LOGIN: сервис временно недоступен.</summary>
    public const ushort LoginErrorServiceTempUnavailable = 0x0002;
    /// <summary>Ошибка LOGIN: аккаунт заблокирован (бан).</summary>
    public const ushort LoginErrorAccountBanned = 0x0003;
    /// <summary>Ошибка LOGIN: неверный пароль (хэш не совпал).</summary>
    public const ushort LoginErrorWrongPassword = 0x0004;
    /// <summary>Ошибка LOGIN: невалидная попытка входа (ошибка формата данных).</summary>
    public const ushort LoginErrorInvalidLogin = 0x0005;

    // --- Коды причины разрыва соединения BYE ---
    /// <summary>Причина BYE: сервер завершает работу (shutdown).</summary>
    public const ushort ByeReasonSrvShutdown = 0x0001;
    /// <summary>Причина BYE: выполнен новый вход с этого аккаунта (старая сессия вытеснена).</summary>
    public const ushort ByeReasonCliNewLogin = 0x0002;
    /// <summary>Причина BYE: аккаунт принудительно отключен администратором (kick).</summary>
    public const ushort ByeReasonAccountKicked = 0x0003;
    /// <summary>Причина BYE: неверный порядковый номер пакета (sequence mismatch).</summary>
    public const ushort ByeReasonIncorrectSeq = 0x0004;
    /// <summary>Причина BYE: получен неизвестный или недопустимый тип BEX.</summary>
    public const ushort ByeReasonIncorrectBexType = 0x0005;
    /// <summary>Причина BYE: получен неизвестный или недопустимый подтип BEX.</summary>
    public const ushort ByeReasonIncorrectBexSub = 0x0006;
    /// <summary>Причина BYE: нарушение последовательности шагов протокола.</summary>
    public const ushort ByeReasonIncorrectBexStep = 0x0007;
    /// <summary>Причина BYE: таймаут бездействия (отсутствие keepalive).</summary>
    public const ushort ByeReasonTimeout = 0x0008;
    /// <summary>Причина BYE: пакет содержит недопустимый или поврежденный wTLD.</summary>
    public const ushort ByeReasonIncorrectWtld = 0x0009;
    /// <summary>Причина BYE: запрошенное действие не разрешено для данного клиента.</summary>
    public const ushort ByeReasonNotAllowed = 0x000A;
    /// <summary>Причина BYE: флудинг (превышена частота отправки запросов).</summary>
    public const ushort ByeReasonFlooding = 0x000B;

    // --- Коды результатов регистрации ---
    /// <summary>Результат регистрации: успешно.</summary>
    public const ushort RegResSuccess = 0x0000;
    /// <summary>Результат регистрации: регистрация новых аккаунтов отключена на сервере.</summary>
    public const ushort RegResDisabled = 0x0001;
    /// <summary>Результат регистрации: аккаунт с таким именем уже существует.</summary>
    public const ushort RegResAccountExists = 0x0002;
    /// <summary>Результат регистрации: недопустимое имя аккаунта.</summary>
    public const ushort RegResBadAccountName = 0x0003;
    /// <summary>Результат регистрации: некорректный запрос (отсутствуют обязательные поля).</summary>
    public const ushort RegResBadRequest = 0x0004;
    /// <summary>Результат регистрации: неверный административный ключ сервера.</summary>
    public const ushort RegResBadServerKey = 0x0005;
    /// <summary>Результат регистрации: сервис временно недоступен.</summary>
    public const ushort RegResServiceTempUnavailable = 0x0006;
    /// <summary>Результат регистрации: для завершения требуется указать email.</summary>
    public const ushort RegResEmailRequired = 0x0007;

    // ========================================================================
    // BEX 0x0002 — Contact List (Список контактов)
    // ========================================================================

    /// <summary>Тип BEX: Contact List (0x0002) — управление списком контактов.</summary>
    public const ushort BexContactList = 0x0002;
    /// <summary>Подтип: CLI_PARAMS (0x0001) — запрос параметров и лимитов списка контактов.</summary>
    public const ushort BexClCliParams = 0x0001;
    /// <summary>Подтип: SRV_PARAMS_REPLY (0x0002) — ответ с параметрами и лимитами списка контактов.</summary>
    public const ushort BexClSrvParamsReply = 0x0002;
    /// <summary>Подтип: CLI_REQUEST (0x0003) — запрос полной копии списка контактов с сервера.</summary>
    public const ushort BexClCliRequest = 0x0003;
    /// <summary>Подтип: SRV_REPLY (0x0004) — сервер возвращает данные списка контактов (BLK blob).</summary>
    public const ushort BexClSrvReply = 0x0004;
    /// <summary>Подтип: CLI_VERIFY (0x0005) — запрос MD5-хэша для сверки локальной копии списка.</summary>
    public const ushort BexClCliVerify = 0x0005;
    /// <summary>Подтип: SRV_VERIFY_REPLY (0x0006) — сервер возвращает MD5-хэш текущей копии списка.</summary>
    public const ushort BexClSrvVerifyReply = 0x0006;
    /// <summary>Подтип: CLI_ADD_ITEM (0x0007) — добавление нового элемента.</summary>
    public const ushort BexClCliAddItem = 0x0007;
    /// <summary>Подтип: SRV_ADD_ITEM_REPLY (0x0008) — результат добавления элемента и его новый ID.</summary>
    public const ushort BexClSrvAddItemReply = 0x0008;
    /// <summary>Подтип: CLI_DEL_ITEM (0x0009) — удаление элемента из списка контактов.</summary>
    public const ushort BexClCliDelItem = 0x0009;
    /// <summary>Подтип: SRV_DEL_ITEM_REPLY (0x000A) — результат удаления элемента.</summary>
    public const ushort BexClSrvDelItemReply = 0x000A;
    /// <summary>Подтип: CLI_UPD_ITEM (0x000B) — обновление данных существующего элемента.</summary>
    public const ushort BexClCliUpdItem = 0x000B;
    /// <summary>Подтип: SRV_UPD_ITEM_REPLY (0x000C) — результат обновления элемента.</summary>
    public const ushort BexClSrvUpdItemReply = 0x000C;
    /// <summary>Подтип: CLI/SRV_AUTH_REQUEST (0x000D) — запрос авторизации контакта.</summary>
    public const ushort BexClCliSrvAuthRequest = 0x000D;
    /// <summary>Подтип: CLI/SRV_AUTH_REPLY (0x000E) — ответ на запрос авторизации.</summary>
    public const ushort BexClCliSrvAuthReply = 0x000E;
    /// <summary>Подтип: CLI/SRV_AUTH_REVOKE (0x000F) — отзыв ранее выданной авторизации.</summary>
    public const ushort BexClCliSrvAuthRevoke = 0x000F;
    /// <summary>Подтип: CLI_REQ_OFFAUTH (0x0010) — запрос накопленных офлайн-сообщений авторизации.</summary>
    public const ushort BexClCliReqOffauth = 0x0010;
    /// <summary>Подтип: SRV_DONE_OFFAUTH (0x0011) — уведомление об отправке всех офлайн-сообщений авторизации.</summary>
    public const ushort BexClSrvDoneOffauth = 0x0011;
    /// <summary>Подтип: CLI_DEL_OFFAUTH (0x0012) — команда серверу удалить обработанные офлайн-сообщения.</summary>
    public const ushort BexClCliDelOffauth = 0x0012;
    /// <summary>Подтип: SRV_ITEM_OPER (0x0013) — серверное уведомление об изменении элемента в списке.</summary>
    public const ushort BexClSrvItemOper = 0x0013;
    /// <summary>Подтип: SRV_BEGIN_UPDATE (0x0014) — сервер начинает массовое обновление списка контактов.</summary>
    public const ushort BexClSrvBeginUpdate = 0x0014;
    /// <summary>Подтип: SRV_END_UPDATE (0x0015) — сервер завершает массовое обновление списка контактов.</summary>
    public const ushort BexClSrvEndUpdate = 0x0015;

    // --- Типы элементов списка контактов ---
    /// <summary>Тип элемента: группа контактов.</summary>
    public const ushort ClItemTypeGroup = 0x0001;
    /// <summary>Тип элемента: контакт.</summary>
    public const ushort ClItemTypeContact = 0x0002;
    /// <summary>Тип элемента: внешний транспорт.</summary>
    public const ushort ClItemTypeTransport = 0x0003;
    /// <summary>Тип элемента: заметка.</summary>
    public const ushort ClItemTypeNote = 0x0004;

    // --- Типы приватности контактов ---
    /// <summary>Приватность: элемент виден всем (по умолчанию).</summary>
    public const byte ClPrivTypeNone = 0x00;
    /// <summary>Приватность: виден только пользователям из списка видимости.</summary>
    public const byte ClPrivTypeVisibleList = 0x01;
    /// <summary>Приватность: не виден пользователям из списка невидимости.</summary>
    public const byte ClPrivTypeInvisibleList = 0x02;
    /// <summary>Приватность: игнорировать сообщения от всех.</summary>
    public const byte ClPrivTypeIgnoreList = 0x03;
    /// <summary>Приватность: игнорировать всех, кто не в списке контактов.</summary>
    public const byte ClPrivTypeIgnoreNotInList = 0x04;

    // --- Типы заметок ---
    /// <summary>Тип заметки: обычный текст.</summary>
    public const byte ClNoteTypeText = 0x00;
    /// <summary>Тип заметки: команда для выполнения.</summary>
    public const byte ClNoteTypeCommand = 0x01;
    /// <summary>Тип заметки: гиперссылка (URL).</summary>
    public const byte ClNoteTypeLink = 0x02;
    /// <summary>Тип заметки: адрес электронной почты.</summary>
    public const byte ClNoteTypeEmail = 0x03;
    /// <summary>Тип заметки: номер телефона.</summary>
    public const byte ClNoteTypePhone = 0x04;

    // --- Коды результата добавления ---
    /// <summary>Результат добавления: успешно.</summary>
    public const ushort AddResSuccess = 0x0000;
    /// <summary>Результат добавления: неверный тип элемента.</summary>
    public const ushort AddResErrorWrongItemType = 0x0001;
    /// <summary>Результат добавления: неверный ID родительской группы.</summary>
    public const ushort AddResErrorWrongParentGroup = 0x0002;
    /// <summary>Результат добавления: превышена лимитная длина имени.</summary>
    public const ushort AddResErrorNameLenLimit = 0x0003;
    /// <summary>Результат добавления: недопустимое имя.</summary>
    public const ushort AddResErrorWrongName = 0x0004;
    /// <summary>Результат добавления: элемент с таким именем уже существует.</summary>
    public const ushort AddResErrorItemAlreadyExists = 0x0005;
    /// <summary>Результат добавления: достигнут максимальный лимит элементов.</summary>
    public const ushort AddResErrorItemLimitReached = 0x0006;
    /// <summary>Результат добавления: некорректный запрос.</summary>
    public const ushort AddResErrorBadRequest = 0x0007;
    /// <summary>Результат добавления: недопустимые sTLD для данного типа элемента.</summary>
    public const ushort AddResErrorBadItemStld = 0x0008;
    /// <summary>Результат добавления: действие не разрешено сервером.</summary>
    public const ushort AddResErrorNotAllowed = 0x0009;

    // --- Коды результата удаления ---
    /// <summary>Результат удаления: успешно.</summary>
    public const ushort DelResSuccess = 0x0000;
    /// <summary>Результат удаления: элемент не найден.</summary>
    public const ushort DelResErrorNotFound = 0x0001;
    /// <summary>Результат удаления: действие не разрешено.</summary>
    public const ushort DelResErrorNotAllowed = 0x0002;
    /// <summary>Результат удаления: группа не пуста.</summary>
    public const ushort DelResErrorGroupNotEmpty = 0x0003;

    // --- Коды результата обновления ---
    /// <summary>Результат обновления: успешно.</summary>
    public const ushort UpdResSuccess = 0x0000;
    /// <summary>Результат обновления: элемент не найден.</summary>
    public const ushort UpdResErrorNotFound = 0x0001;
    /// <summary>Результат обновления: неверный ID родительской группы.</summary>
    public const ushort UpdResErrorWrongParentGroup = 0x0002;
    /// <summary>Результат обновления: превышена лимитная длина имени.</summary>
    public const ushort UpdResErrorNameLenLimit = 0x0003;
    /// <summary>Результат обновления: недопустимое имя.</summary>
    public const ushort UpdResErrorWrongName = 0x0004;
    /// <summary>Результат обновления: элемент с таким именем уже существует.</summary>
    public const ushort UpdResErrorItemAlreadyExists = 0x0005;
    /// <summary>Результат обновления: некорректный запрос.</summary>
    public const ushort UpdResErrorBadRequest = 0x0006;
    /// <summary>Результат обновления: недопустимые sTLD для данного типа элемента.</summary>
    public const ushort UpdResErrorBadItemStld = 0x0007;
    /// <summary>Результат обновления: действие не разрешено сервером.</summary>
    public const ushort UpdResErrorNotAllowed = 0x0008;

    // --- Коды ответов авторизации ---
    /// <summary>Ответ на авторизацию: запрос принят (подтвержден).</summary>
    public const ushort AuthReplyGranted = 0x0001;
    /// <summary>Ответ на авторизацию: запрос отклонен.</summary>
    public const ushort AuthReplyDenied = 0x0002;

    // --- Коды операций SRV_ITEM_OPER ---
    /// <summary>Код операции: добавление элемента в список.</summary>
    public const ushort OperAddItem = 0x0001;
    /// <summary>Код операции: удаление элемента из списка.</summary>
    public const ushort OperDelItem = 0x0002;
    /// <summary>Код операции: обновление данных элемента.</summary>
    public const ushort OperUpdItem = 0x0003;

    // ========================================================================
    // BEX 0x0003 — Presence (Присутствие и статусы)
    // ========================================================================

    /// <summary>Тип BEX: Presence (0x0003) — управление статусами присутствия.</summary>
    public const ushort BexPresence = 0x0003;
    /// <summary>Подтип: CLI_PARAMS (0x0001) — запрос параметров presence.</summary>
    public const ushort BexPresCliParams = 0x0001;
    /// <summary>Подтип: SRV_PARAMS_REPLY (0x0002) — ответ с параметрами presence.</summary>
    public const ushort BexPresSrvParamsReply = 0x0002;
    /// <summary>Подтип: CLI_SET_PRES_INFO (0x0003) — клиент устанавливает свои возможности и тип.</summary>
    public const ushort BexPresCliSetPresInfo = 0x0003;
    /// <summary>Подтип: CLI_SET_STATUS (0x0004) — клиент устанавливает текущий статус присутствия.</summary>
    public const ushort BexPresCliSetStatus = 0x0004;
    /// <summary>Подтип: CLI_ACTIVATE (0x0005) — активация рассылки статуса присутствия контактам.</summary>
    public const ushort BexPresCliActivate = 0x0005;
    /// <summary>Подтип: SRV_CONTACT_ONLINE (0x0006) — сервер уведомляет, что контакт перешел в онлайн.</summary>
    public const ushort BexPresSrvContactOnline = 0x0006;
    /// <summary>Подтип: SRV_CONTACT_OFFLINE (0x0007) — сервер уведомляет, что контакт перешел в оффлайн.</summary>
    public const ushort BexPresSrvContactOffline = 0x0007;
    /// <summary>Подтип: CLI_REQ_PRES_INFO (0x0008) — клиент запрашивает собственную информацию о присутствии.</summary>
    public const ushort BexPresCliReqPresInfo = 0x0008;
    /// <summary>Подтип: SRV_PRES_INFO (0x0009) — сервер возвращает текущую информацию о присутствии клиента.</summary>
    public const ushort BexPresSrvPresInfo = 0x0009;
    /// <summary>Подтип: SRV_MAIL_NOTIF (0x000A) — сервер отправляет уведомление о новой почте.</summary>
    public const ushort BexPresSrvMailNotif = 0x000A;
    /// <summary>Подтип: CLI_REQ_OWN_MAIL_URL (0x000B) — запрос URL веб-интерфейса почтового ящика.</summary>
    public const ushort BexPresCliReqOwnMailUrl = 0x000B;
    /// <summary>Подтип: SRV_OWN_MAIL_URL (0x000C) — сервер возвращает URL веб-интерфейса почтового ящика.</summary>
    public const ushort BexPresSrvOwnMailUrl = 0x000C;

    // --- Значения статусов присутствия ---
    /// <summary>Статус: онлайн.</summary>
    public const uint PresStatusOnline = 0x0000;
    /// <summary>Статус: невидимка.</summary>
    public const uint PresStatusInvisible = 0x0001;
    /// <summary>Статус: невидимка для всех.</summary>
    public const uint PresStatusInvisibleForAll = 0x0002;
    /// <summary>Статус: свободен для общения.</summary>
    public const uint PresStatusFreeForChat = 0x0003;
    /// <summary>Статус: дома.</summary>
    public const uint PresStatusAtHome = 0x0004;
    /// <summary>Статус: на работе.</summary>
    public const uint PresStatusAtWork = 0x0005;
    /// <summary>Статус: обед.</summary>
    public const uint PresStatusLunch = 0x0006;
    /// <summary>Статус: отошел.</summary>
    public const uint PresStatusAway = 0x0007;
    /// <summary>Статус: недоступен.</summary>
    public const uint PresStatusNotAvailable = 0x0008;
    /// <summary>Статус: занят.</summary>
    public const uint PresStatusOccupied = 0x0009;
    /// <summary>Статус: не беспокоить.</summary>
    public const uint PresStatusDoNotDisturb = 0x000A;
    /// <summary>Статус: пользовательский/разработческий статус (начиная с этого значения).</summary>
    public const uint PresStatusDeveloper = 0x80000000;

    // --- Возможности клиента / Capabilities ---
    /// <summary>Возможность: поддержка сообщений в кодировке UTF-8 (обязательная).</summary>
    public const ushort CapMsgsUtf8 = 0x0001;
    /// <summary>Возможность: поддержка сообщений в формате RTF.</summary>
    public const ushort CapMsgsRtf = 0x0002;
    /// <summary>Возможность: поддержка сообщений в формате HTML.</summary>
    public const ushort CapMsgsHtml = 0x0003;
    /// <summary>Возможность: поддержка шифрования сообщений.</summary>
    public const ushort CapMsgsEncrypt = 0x0004;
    /// <summary>Возможность: поддержка уведомлений о наборе текста.</summary>
    public const ushort CapNotifsTyping = 0x0005;
    /// <summary>Возможность: поддержка пользовательских аватаров.</summary>
    public const ushort CapAvatars = 0x0006;
    /// <summary>Возможность: поддержка передачи файлов.</summary>
    public const ushort CapFileTransfer = 0x0007;
    /// <summary>Возможность: поддержка внешних транспортов.</summary>
    public const ushort CapTransports = 0x0008;
    /// <summary>Возможность: поддержка будильников/сигнализаций.</summary>
    public const ushort CapNotifsAlarm = 0x0009;
    /// <summary>Возможность: поддержка уведомлений о новой почте.</summary>
    public const ushort CapNotifsMail = 0x000A;

    // --- Типы клиентов ---
    /// <summary>Тип клиента: обычный пользователь.</summary>
    public const ushort ClientTypeUser = 0x0001;
    /// <summary>Тип клиента: бот или автоматизированный скрипт.</summary>
    public const ushort ClientTypeBot = 0x0002;
    /// <summary>Тип клиента: сервис или шлюз.</summary>
    public const ushort ClientTypeService = 0x0003;

    // --- Флаги Presence ---
    /// <summary>Требуемый флаг дополнительной информации: имя хоста (hostname).</summary>
    public const uint PresReqFlagHostname = 0x00000001;
    /// <summary>Флаг клиента: запрашивать получение имени и версии клиента контакта.</summary>
    public const uint PresCfRcvClientNameAndVer = 0x00000001;
    /// <summary>Флаг клиента: запрашивать получение информации об ОС контакта.</summary>
    public const uint PresCfRcvOsInformation = 0x00000002;
    /// <summary>Флаг клиента: запрашивать получение дополнительного описания клиента.</summary>
    public const uint PresCfRcvClientDescription = 0x00000004;
    /// <summary>Флаг клиента: запрашивать получение блока идентификации клиента (ID BLK).</summary>
    public const uint PresCfRcvClientIdBlk = 0x00000008;

    // ========================================================================
    // BEX 0x0004 — Instant Messaging (Обмен сообщениями) 
    // ========================================================================

    /// <summary>Тип BEX: Instant Messaging (0x0004) — отправка и получение сообщений.</summary>
    public const ushort BexIm = 0x0004;
    /// <summary>Подтип: CLI_PARAMS (0x0001) — запрос параметров мгновенных сообщений.</summary>
    public const ushort BexImCliParams = 0x0001;
    /// <summary>Подтип: SRV_PARAMS_REPLY (0x0002) — ответ с параметрами мгновенных сообщений.</summary>
    public const ushort BexImSrvParamsReply = 0x0002;
    /// <summary>Подтип: CLI_REQ_OFFLINE (0x0003) — запрос накопленных офлайн-сообщений.</summary>
    public const ushort BexImCliReqOffline = 0x0003;
    /// <summary>Подтип: SRV_DONE_OFFLINE (0x0004) — уведомление об отправке всех офлайн-сообщений.</summary>
    public const ushort BexImSrvDoneOffline = 0x0004;
    /// <summary>Подтип: CLI_DEL_OFFLINE (0x0005) — команда серверу удалить обработанные офлайн-сообщения.</summary>
    public const ushort BexImCliDelOffline = 0x0005;
    /// <summary>Подтип: CLI_MESSAGE (0x0006) — клиент отправляет сообщение.</summary>
    public const ushort BexImCliMessage = 0x0006;
    /// <summary>Подтип: SRV_MESSAGE (0x0007) — клиент получает сообщение.</summary>
    public const ushort BexImSrvMessage = 0x0007;
    /// <summary>Подтип: CLI/SRV_MSG_REPORT (0x0008) — подтверждение доставки сообщения.</summary>
    public const ushort BexImCliSrvMsgReport = 0x0008;
    /// <summary>Подтип: CLI/SRV_NOTIFY (0x0009) — служебное уведомление.</summary>
    public const ushort BexImCliSrvNotify = 0x0009;
    /// <summary>Подтип: CLI/SRV_ENCRYPT_KEY_REQ (0x000A) — запрос публичного ключа для шифрования.</summary>
    public const ushort BexImCliSrvEncryptKeyReq = 0x000A;
    /// <summary>Подтип: CLI/SRV_ENCRYPT_KEY_REPLY (0x000B) — ответ с публичным ключом или типом шифрования.</summary>
    public const ushort BexImCliSrvEncryptKeyReply = 0x000B;
    /// <summary>Подтип: CLI_MULTIPLE_MSG (0x000C) — отправка сообщения нескольким контактам.</summary>
    public const ushort BexImCliMultipleMsg = 0x000C;
    /// <summary>Максимальное количество sTLD (получателей) в одном пакете CLI_MULTIPLE_MSG.</summary>
    public const ushort ImMaxMultipleStldPerBex = 30;

    // --- Типы сообщений ---
    /// <summary>Тип сообщения: текст в кодировке UTF-8 (базовый).</summary>
    public const uint MsgTypeUtf8 = 0x0001;
    /// <summary>Тип сообщения: форматированный текст RTF.</summary>
    public const uint MsgTypeRtf = 0x0002;
    /// <summary>Тип сообщения: разметка HTML.</summary>
    public const uint MsgTypeHtml = 0x0003;

    // --- Типы и значения уведомлений ---
    /// <summary>Тип уведомления: пользователь печатает текст.</summary>
    public const uint NotifTypeUserTyping = 0x0001;
    /// <summary>Тип уведомления: сигнализация (будильник).</summary>
    public const uint NotifTypeWakeAlarm = 0x0002;
    /// <summary>Значение: пользователь начал печатать.</summary>
    public const uint NotifValueUserTypingStart = 0x0001;
    /// <summary>Значение: пользователь закончил печатать.</summary>
    public const uint NotifValueUserTypingFinish = 0x0002;
    /// <summary>Значение: команда воспроизвести сигнализацию.</summary>
    public const uint NotifValueWakeAlarmPlay = 0x0003;
    /// <summary>Значение: команда ожидать сигнализацию.</summary>
    public const uint NotifValueWakeAlarmWait = 0x0004;

    // --- Типы шифрования ---
    /// <summary>Тип шифрования: отключено или не поддерживается.</summary>
    public const uint EncTypeDisabled = 0x0000;
    /// <summary>Тип шифрования: встроенное шифрование OBIMP.</summary>
    public const uint EncTypeObimp = 0x0001;
    /// <summary>Тип шифрования: PGP.</summary>
    public const uint EncTypePgp = 0x0002;

    // ========================================================================
    // BEX 0x0005 — Users Directory (Каталог пользователей)
    // ========================================================================

    /// <summary>Тип BEX: Users Directory (0x0005) — поиск и управление данными пользователей.</summary>
    public const ushort BexUsersDirectory = 0x0005;
    /// <summary>Подтип: CLI_PARAMS (0x0001) — запрос параметров каталога пользователей.</summary>
    public const ushort BexUdCliParams = 0x0001;
    /// <summary>Подтип: SRV_PARAMS_REPLY (0x0002) — ответ с параметрами каталога пользователей.</summary>
    public const ushort BexUdSrvParamsReply = 0x0002;
    /// <summary>Подтип: CLI_DETAILS_REQ (0x0003) — запрос детальной информации об аккаунте.</summary>
    public const ushort BexUdCliDetailsReq = 0x0003;
    /// <summary>Подтип: SRV_DETAILS_REQ_REPLY (0x0004) — ответ с детальной информацией.</summary>
    public const ushort BexUdSrvDetailsReqReply = 0x0004;
    /// <summary>Подтип: CLI_DETAILS_UPD (0x0005) — обновление данных собственного аккаунта.</summary>
    public const ushort BexUdCliDetailsUpd = 0x0005;
    /// <summary>Подтип: SRV_DETAILS_UPD_REPLY (0x0006) — результат обновления данных аккаунта.</summary>
    public const ushort BexUdSrvDetailsUpdReply = 0x0006;
    /// <summary>Подтип: CLI_SEARCH (0x0007) — поиск пользователей по заданным критериям.</summary>
    public const ushort BexUdCliSearch = 0x0007;
    /// <summary>Подтип: SRV_SEARCH_REPLY (0x0008) — результаты поиска пользователей.</summary>
    public const ushort BexUdSrvSearchReply = 0x0008;
    /// <summary>Подтип: CLI_SECURE_UPD (0x0009) — обновление защищенных данных (email/пароль).</summary>
    public const ushort BexUdCliSecureUpd = 0x0009;
    /// <summary>Подтип: SRV_SECURE_UPD_REPLY (0x000A) — результат обновления защищенных данных.</summary>
    public const ushort BexUdSrvSecureUpdReply = 0x000A;

    // --- Коды результатов ---
    /// <summary>Результат запроса деталей: успешно.</summary>
    public const ushort DetailsResSuccess = 0x0000;
    /// <summary>Результат запроса деталей: аккаунт не найден.</summary>
    public const ushort DetailsResNotFound = 0x0001;
    /// <summary>Результат запроса деталей: слишком много запросов.</summary>
    public const ushort DetailsResTooManyRequests = 0x0002;
    /// <summary>Результат запроса деталей: сервис временно недоступен.</summary>
    public const ushort DetailsResServiceTempUnavailable = 0x0003;

    /// <summary>Результат обновления деталей: успешно.</summary>
    public const ushort UpdDetailsResSuccess = 0x0000;
    /// <summary>Результат обновления деталей: некорректный запрос.</summary>
    public const ushort UpdDetailsResBadRequest = 0x0001;
    /// <summary>Результат обновления деталей: сервис временно недоступен.</summary>
    public const ushort UpdDetailsResServiceTempUnavailable = 0x0002;
    /// <summary>Результат обновления деталей: действие не разрешено.</summary>
    public const ushort UpdDetailsResNotAllowed = 0x0003;

    /// <summary>Результат поиска: успешно.</summary>
    public const ushort SearchResSuccess = 0x0000;
    /// <summary>Результат поиска: не найдено ни одного совпадения.</summary>
    public const ushort SearchResNotFound = 0x0001;
    /// <summary>Результат поиска: некорректный запрос.</summary>
    public const ushort SearchResBadRequest = 0x0002;
    /// <summary>Результат поиска: слишком много запросов.</summary>
    public const ushort SearchResTooManyRequests = 0x0003;
    /// <summary>Результат поиска: сервис временно недоступен.</summary>
    public const ushort SearchResServiceTempUnavailable = 0x0004;

    // --- Пол и Знаки зодиака ---
    /// <summary>Пол: не указан.</summary>
    public const byte GenderNotSpecified = 0x00;
    /// <summary>Пол: женский.</summary>
    public const byte GenderFemale = 0x01;
    /// <summary>Пол: мужской.</summary>
    public const byte GenderMale = 0x02;

    /// <summary>Знак зодиака: Овен.</summary>
    public const byte ZodiacAries = 0x01;
    /// <summary>Знак зодиака: Телец.</summary>
    public const byte ZodiacTaurus = 0x02;
    /// <summary>Знак зодиака: Близнецы.</summary>
    public const byte ZodiacGemini = 0x03;
    /// <summary>Знак зодиака: Рак.</summary>
    public const byte ZodiacCancer = 0x04;
    /// <summary>Знак зодиака: Лев.</summary>
    public const byte ZodiacLeo = 0x05;
    /// <summary>Знак зодиака: Дева.</summary>
    public const byte ZodiacVirgo = 0x06;
    /// <summary>Знак зодиака: Весы.</summary>
    public const byte ZodiacLibra = 0x07;
    /// <summary>Знак зодиака: Скорпион.</summary>
    public const byte ZodiacScorpio = 0x08;
    /// <summary>Знак зодиака: Стрелец.</summary>
    public const byte ZodiacSagittarius = 0x09;
    /// <summary>Знак зодиака: Козерог.</summary>
    public const byte ZodiacCapricorn = 0x0A;
    /// <summary>Знак зодиака: Водолей.</summary>
    public const byte ZodiacAquarius = 0x0B;
    /// <summary>Знак зодиака: Рыбы.</summary>
    public const byte ZodiacPisces = 0x0C;

    // --- Флаги поиска ---
    /// <summary>Флаг картинки статуса в поиске: использовать пользовательскую картинку статуса.</summary>
    public const uint SearchStPicFlagCustom = 0x00010000;

    // ========================================================================
    // BEX 0x0006 — User Avatars (Аватары пользователей)
    // ========================================================================

    /// <summary>Тип BEX: User Avatars (0x0006) — загрузка и получение аватаров.</summary>
    public const ushort BexAvatars = 0x0006;
    /// <summary>Подтип: CLI_PARAMS (0x0001) — запрос параметров и лимитов аватаров.</summary>
    public const ushort BexUaCliParams = 0x0001;
    /// <summary>Подтип: SRV_PARAMS_REPLY (0x0002) — ответ с параметрами и MD5-хэшем текущего аватара.</summary>
    public const ushort BexUaSrvParamsReply = 0x0002;
    /// <summary>Подтип: CLI_AVATAR_REQ (0x0003) — запрос файла аватара по его MD5-хэшу.</summary>
    public const ushort BexUaCliAvatarReq = 0x0003;
    /// <summary>Подтип: SRV_AVATAR_REPLY (0x0004) — сервер возвращает файл аватара или ошибку.</summary>
    public const ushort BexUaSrvAvatarReply = 0x0004;
    /// <summary>Подтип: CLI_AVATAR_SET (0x0005) — клиент устанавливает или удаляет свой аватар.</summary>
    public const ushort BexUaCliAvatarSet = 0x0005;
    /// <summary>Подтип: SRV_AVATAR_SET_REPLY (0x0006) — результат установки или удаления аватара.</summary>
    public const ushort BexUaSrvAvatarSetReply = 0x0006;

    // --- Коды результата ЗАПРОСА аватара ---
    /// <summary>Результат запроса аватара: успешно.</summary>
    public const ushort UaAvatarReqSuccess = 0x0000;
    /// <summary>Результат запроса аватара: аватар с таким хэшем не найден.</summary>
    public const ushort UaAvatarReqNotFound = 0x0001;
    /// <summary>Результат запроса аватара: действие не разрешено.</summary>
    public const ushort UaAvatarReqNotAllowed = 0x0002;

    // --- Коды результата УСТАНОВКИ аватара ---
    /// <summary>Результат установки аватара: успешно.</summary>
    public const ushort UaAvatarSetSuccess = 0x0000;
    /// <summary>Результат установки аватара: хэш файла не совпадает с переданным.</summary>
    public const ushort UaAvatarSetBadMd5 = 0x0001;
    /// <summary>Результат установки аватара: действие не разрешено.</summary>
    public const ushort UaAvatarSetNotAllowed = 0x0002;
    /// <summary>Результат установки аватара: сервис временно недоступен.</summary>
    public const ushort UaAvatarSetTempUnavailable = 0x0003;
    /// <summary>Результат установки аватара: размер файла превышает лимит.</summary>
    public const ushort UaAvatarSetTooBig = 0x0004;
    /// <summary>Результат установки аватара: размер файла слишком мал.</summary>
    public const ushort UaAvatarSetTooSmall = 0x0005;
    /// <summary>Результат установки аватара: аватар заблокирован.</summary>
    public const ushort UaAvatarSetBanned = 0x0006;
    /// <summary>Результат установки аватара: недопустимый тип файла (требуется PNG).</summary>
    public const ushort UaAvatarSetInvalidType = 0x0007;
    /// <summary>Результат установки аватара: прочая ошибка сервера.</summary>
    public const ushort UaAvatarSetOtherError = 0x0008;

    // ========================================================================
    // BEX 0x0007 — File Transfer (Передача файлов)
    // ========================================================================

    /// <summary>Тип BEX: File Transfer (0x0007) — прямая, обратная и прокси-передача файлов.</summary>
    public const ushort BexFileTransfer = 0x0007;
    /// <summary>Подтип: CLI_PARAMS (0x0001) — запрос параметров передачи файлов.</summary>
    public const ushort BexFtCliParams = 0x0001;
    /// <summary>Подтип: SRV_PARAMS_REPLY (0x0002) — ответ с параметрами передачи файлов.</summary>
    public const ushort BexFtSrvParamsReply = 0x0002;
    /// <summary>Подтип: CLI_SRV_SEND_FILE_REQUEST (0x0003) — запрос на отправку файла.</summary>
    public const ushort BexFtCliSrvSendFileRequest = 0x0003;
    /// <summary>Подтип: CLI_SRV_SEND_FILE_REPLY (0x0004) — ответ на запрос отправки файла.</summary>
    public const ushort BexFtCliSrvSendFileReply = 0x0004;
    /// <summary>Подтип: CLI_SRV_CONTROL (0x0005) — управляющее сообщение передачи файлов.</summary>
    public const ushort BexFtCliSrvControl = 0x0005;
    /// <summary>Подтип: DIR_PROX_ERROR (0x0101) — ошибка, прерывающая процесс.</summary>
    public const ushort BexFtDirProxError = 0x0101;
    /// <summary>Подтип: DIR_PROX_HELLO (0x0102) — приветствие при установлении соединения.</summary>
    public const ushort BexFtDirProxHello = 0x0102;
    /// <summary>Подтип: DIR_PROX_FILE (0x0103) — передача параметров отправляемого файла.</summary>
    public const ushort BexFtDirProxFile = 0x0103;
    /// <summary>Подтип: DIR_PROX_FILE_REPLY (0x0104) — ответ получателя с позицией возобновления.</summary>
    public const ushort BexFtDirProxFileReply = 0x0104;
    /// <summary>Подтип: DIR_PROX_FILE_DATA (0x0105) — передача блока данных файла.</summary>
    public const ushort BexFtDirProxFileData = 0x0105;

    // --- Коды ответа, управления и ошибок передачи ---
    /// <summary>Код ответа: файл принят к передаче.</summary>
    public const ushort FtReplyCodeAccept = 0x0001;
    /// <summary>Код ответа: передача файла отклонена пользователем.</summary>
    public const ushort FtReplyCodeDecline = 0x0002;
    /// <summary>Код ответа: передача файлов отключена в настройках.</summary>
    public const ushort FtReplyCodeDisabled = 0x0003;
    /// <summary>Код ответа: передача не разрешена.</summary>
    public const ushort FtReplyCodeNotAllowed = 0x0004;

    /// <summary>Управляющий код: отмена передачи файла.</summary>
    public const ushort FtControlCodeCancel = 0x0001;
    /// <summary>Управляющий код: прямое соединение не удалось.</summary>
    public const ushort FtControlCodeDirectFailed = 0x0002;
    /// <summary>Управляющий код: прямое соединение не удалось, попробовать обратное.</summary>
    public const ushort FtControlCodeDirectFailedTryReverse = 0x0003;
    /// <summary>Управляющий код: прямое соединение не удалось, попробовать через прокси.</summary>
    public const ushort FtControlCodeDirectFailedTryProxy = 0x0004;
    /// <summary>Управляющий код: соединение с прокси-сервером не удалось.</summary>
    public const ushort FtControlCodeProxyFailed = 0x0005;
    /// <summary>Управляющий код: готов к началу передачи данных.</summary>
    public const ushort FtControlCodeReady = 0x0006;

    /// <summary>Код ошибки: таймаут ожидания данных.</summary>
    public const ushort FtErrorCodeTimeout = 0x0001;
    /// <summary>Код ошибки: неверный уникальный ID передачи файла.</summary>
    public const ushort FtErrorCodeWrongUniqFtId = 0x0002;
    /// <summary>Код ошибки: недопустимое имя файла.</summary>
    public const ushort FtErrorCodeWrongFileName = 0x0003;
    /// <summary>Код ошибки: недопустимый относительный путь.</summary>
    public const ushort FtErrorCodeWrongRelativePath = 0x0004;
    /// <summary>Код ошибки: неверная позиция возобновления.</summary>
    public const ushort FtErrorCodeWrongResumePos = 0x0005;
    /// <summary>Код ошибки: превышен лимит трафика на прокси-сервере.</summary>
    public const ushort FtErrorCodeProxyTrafficLimit = 0x0006;

    // ========================================================================
    // BEX 0x0008 — Transports (Внешние транспорты)
    // ========================================================================

    /// <summary>Тип BEX: Transports (0x0008) — подключение и управление внешними мессенджерами.</summary>
    public const ushort BexTransports = 0x0008;
    /// <summary>Подтип: CLI_PARAMS (0x0001) — запрос параметров транспортов.</summary>
    public const ushort BexTpCliParams = 0x0001;
    /// <summary>Подтип: SRV_PARAMS_REPLY (0x0002) — ответ с параметрами и списком доступных транспортов.</summary>
    public const ushort BexTpSrvParamsReply = 0x0002;
    /// <summary>Подтип: SRV_ITEM_READY (0x0003) — сервер уведомляет, что транспорт готов к командам.</summary>
    public const ushort BexTpSrvItemReady = 0x0003;
    /// <summary>Подтип: CLI_SETTINGS (0x0004) — обновление настроек транспорта.</summary>
    public const ushort BexTpCliSettings = 0x0004;
    /// <summary>Подтип: SRV_SETTINGS_REPLY (0x0005) — результат обновления настроек транспорта.</summary>
    public const ushort BexTpSrvSettingsReply = 0x0005;
    /// <summary>Подтип: CLI_MANAGE (0x0006) — управление подключением транспорта.</summary>
    public const ushort BexTpCliManage = 0x0006;
    /// <summary>Подтип: SRV_TRANSPORT_INFO (0x0007) — уведомление об изменении состояния транспорта.</summary>
    public const ushort BexTpSrvTransportInfo = 0x0007;
    /// <summary>Подтип: SRV_SHOW_NOTIF (0x0008) — запрос на отображение всплывающего уведомления.</summary>
    public const ushort BexTpSrvShowNotif = 0x0008;
    /// <summary>Подтип: SRV_OWN_AVATAR_HASH (0x0009) — уведомление о хэше аватара аккаунта транспорта.</summary>
    public const ushort BexTpSrvOwnAvatarHash = 0x0009;

    // --- Флаги, типы и состояния транспортов ---
    /// <summary>Флаг настроек: скрыть параметры сервера от пользователя в интерфейсе.</summary>
    public const ushort TpSfHideSrvParams = 0x0001;

    /// <summary>Тип опции: логическое значение (Bool).</summary>
    public const ushort TpOtBool = 1;
    /// <summary>Тип опции: байт (Byte).</summary>
    public const ushort TpOtByte = 2;
    /// <summary>Тип опции: слово (Word, 2 байта).</summary>
    public const ushort TpOtWord = 3;
    /// <summary>Тип опции: длинное слово (LongWord, 4 байта).</summary>
    public const ushort TpOtLongword = 4;
    /// <summary>Тип опции: четверное слово (QuadWord, 8 байт).</summary>
    public const ushort TpOtQuadword = 5;
    /// <summary>Тип опции: строка в кодировке UTF-8.</summary>
    public const ushort TpOtUtf8 = 6;

    /// <summary>Флаг опции: отображать как чекбокс.</summary>
    public const uint TpOfCheck = 0x00000001;
    /// <summary>Флаг опции: отображать как редактируемое текстовое поле.</summary>
    public const uint TpOfEdit = 0x00000002;
    /// <summary>Флаг опции: отображать как выпадающий список.</summary>
    public const uint TpOfCombo = 0x00000004;
    /// <summary>Флаг опции: отображать как гиперссылку.</summary>
    public const uint TpOfLink = 0x00000008;
    /// <summary>Флаг опции: изменение этого параметра требует немедленного сохранения.</summary>
    public const uint TpOfChange = 0x00010000;
    /// <summary>Флаг опции: только для чтения.</summary>
    public const uint TpOfReadOnly = 0x00020000;
    /// <summary>Флаг опции: опция отключена.</summary>
    public const uint TpOfDisabled = 0x00040000;

    /// <summary>Результат обновления настроек: успешно.</summary>
    public const ushort TpSetResSuccess = 0x0000;
    /// <summary>Результат обновления настроек: неверный ID транспорта.</summary>
    public const ushort TpSetResErrorWrongId = 0x0001;
    /// <summary>Результат обновления настроек: транспорт не найден.</summary>
    public const ushort TpSetResErrorNotFound = 0x0002;
    /// <summary>Результат обновления настроек: действие не разрешено.</summary>
    public const ushort TpSetResErrorNotAllowed = 0x0003;

    /// <summary>Код управления: инициировать подключение к транспорту.</summary>
    public const ushort TpConManConnect = 0x0001;
    /// <summary>Код управления: изменить статус в транспорте.</summary>
    public const ushort TpConManStatus = 0x0002;
    /// <summary>Код управления: отключиться от транспорта.</summary>
    public const ushort TpConManDisconnect = 0x0003;

    /// <summary>Состояние: успешно залогинен в транспорте.</summary>
    public const ushort TpStateLoggedIn = 0x0000;
    /// <summary>Состояние: не залогинен (отключен).</summary>
    public const ushort TpStateLoggedoff = 0x0001;
    /// <summary>Состояние: статус в транспорте был изменен.</summary>
    public const ushort TpStateStatusChanged = 0x0002;
    /// <summary>Состояние: ошибка подключения к транспорту.</summary>
    public const ushort TpStateConFailed = 0x0003;
    /// <summary>Состояние: невалидный аккаунт транспорта.</summary>
    public const ushort TpStateAccountInvalid = 0x0004;
    /// <summary>Состояние: сервис транспорта временно недоступен.</summary>
    public const ushort TpStateServiceTempUnavailable = 0x0005;
    /// <summary>Состояние: неверный пароль для транспорта.</summary>
    public const ushort TpStateWrongPassword = 0x0006;
    /// <summary>Состояние: невалидный логин для транспорта.</summary>
    public const ushort TpStateInvalidLogin = 0x0007;
    /// <summary>Состояние: вход выполнен с другого устройства.</summary>
    public const ushort TpStateOtherPlaceLogin = 0x0008;
    /// <summary>Состояние: не может войти, попробуйте позже.</summary>
    public const ushort TpStateCantLoginTryLater = 0x0009;
    /// <summary>Состояние: сервис транспорта приостановлен администратором.</summary>
    public const ushort TpStateSrvPaused = 0x000A;
    /// <summary>Состояние: сервис транспорта возобновлен.</summary>
    public const ushort TpStateSrvResumed = 0x000B;
    /// <summary>Состояние: сервис транспорта мигрирован на другой сервер.</summary>
    public const ushort TpStateSrvMigrated = 0x000C;

    // ========================================================================
    // wTLD для BEX 0x0001 — Common
    // ========================================================================
    // --- wTLD для клиентских запросов (CLI) ---
    /// <summary>
    /// wTLD 0x0001 (CLI_HELLO / CLI_LOGIN): Имя аккаунта (UTF8).
    /// </summary>
    public const ushort WtldComCliAccountName = 0x0001;

    /// <summary>
    /// wTLD 0x0002 (CLI_LOGIN): Одноразовый MD5-хэш пароля, сгенерированный клиентом (OctaWord/BLK).
    /// </summary>
    public const ushort WtldComCliLoginMd5Hash = 0x0002;

    /// <summary>wTLD 0x0001 (SRV_HELLO): Код ошибки приветствия (Word).</summary>
    public const ushort WtldComHelloError = 0x0001;

    /// <summary>wTLD 0x0002 (SRV_HELLO): Ключ сервера для генерации MD5-хэша пароля (BLK).</summary>
    public const ushort WtldComServerKey = 0x0002;

    /// <summary>wTLD 0x0003 (SRV_HELLO): Перенаправление, новый хост/IP сервера (UTF8).</summary>
    public const ushort WtldComRedirectHost = 0x0003;

    /// <summary>wTLD 0x0004 (SRV_HELLO): Перенаправление, номер порта нового сервера (LongWord).</summary>
    public const ushort WtldComRedirectPort = 0x0004;

    /// <summary>wTLD 0x0005 (SRV_HELLO): Регистрация включена на сервере (Bool).</summary>
    public const ushort WtldComRegistrationEnabled = 0x0005;

    /// <summary>wTLD 0x0006 (SRV_HELLO): URL веб-страницы для регистрации аккаунта (UTF8).</summary>
    public const ushort WtldComRegistrationUrl = 0x0006;

    /// <summary>wTLD 0x0007 (SRV_HELLO): Сервер требует аутентификацию с открытым текстом пароля (пустой).</summary>
    public const ushort WtldComPlainTextAuth = 0x0007;

    /// <summary>wTLD 0x0008 (SRV_HELLO): Рекомендуемая минимальная версия microOBIMP SDK (LongWord).</summary>
    public const ushort WtldComMinSdkVersion = 0x0008;

    /// <summary>wTLD 0x0001 (SRV_LOGIN_REPLY): Код ошибки входа (Word).</summary>
    public const ushort WtldComLoginError = 0x0001;

    /// <summary>wTLD 0x0002 (SRV_LOGIN_REPLY): Массив поддерживаемых сервером BEX (Word pairs).</summary>
    public const ushort WtldComSupportedBexs = 0x0002;

    /// <summary>wTLD 0x0003 (SRV_LOGIN_REPLY): Максимальная длина данных клиентского BEX (LongWord).</summary>
    public const ushort WtldComMaxBexDataLen = 0x0003;

    /// <summary>wTLD 0x0004 (SRV_LOGIN_REPLY): Новый хост/IP сервера для перенаправления (UTF8).</summary>
    public const ushort WtldComNewServerHost = 0x0004;

    /// <summary>wTLD 0x0005 (SRV_LOGIN_REPLY): Номер порта нового сервера для перенаправления (LongWord).</summary>
    public const ushort WtldComNewServerPort = 0x0005;

    /// <summary>wTLD 0x0006 (SRV_LOGIN_REPLY): Уникальный cookie сервера для быстрого входа (BLK).</summary>
    public const ushort WtldComServerCookie = 0x0006;

    /// <summary>wTLD 0x0007 (SRV_LOGIN_REPLY): URL напоминания пароля при ошибке неверного пароля (UTF8).</summary>
    public const ushort WtldComPasswordReminderUrl = 0x0007;

    /// <summary>wTLD 0x0008 (SRV_LOGIN_REPLY): Массив версий BEX (QuadWord array).</summary>
    public const ushort WtldComBexVersions = 0x0008;

    // ========================================================================
    // wTLD для BEX 0x0002 — Contact List
    // ========================================================================

    /// <summary>wTLD 0x0001 (SRV_PARAMS_REPLY): Максимальное количество групп (LongWord).</summary>
    public const ushort WtldClMaxGroupsCount = 0x0001;

    /// <summary>wTLD 0x0002 (SRV_PARAMS_REPLY): Максимальная длина имени группы в UTF-8 (LongWord).</summary>
    public const ushort WtldClMaxGroupNameLen = 0x0002;

    /// <summary>wTLD 0x0003 (SRV_PARAMS_REPLY): Максимальное количество контактов во всем списке (LongWord).</summary>
    public const ushort WtldClMaxContactsCount = 0x0003;

    /// <summary>wTLD 0x0004 (SRV_PARAMS_REPLY): Максимальная длина имени аккаунта в UTF-8 (LongWord).</summary>
    public const ushort WtldClMaxAccountNameLen = 0x0004;

    /// <summary>wTLD 0x0005 (SRV_PARAMS_REPLY): Максимальная длина имени контакта/транспорта в UTF-8 (LongWord).</summary>
    public const ushort WtldClMaxContactNameLen = 0x0005;

    /// <summary>wTLD 0x0006 (SRV_PARAMS_REPLY): Максимальная длина причины авторизации/отзыва в UTF-8 (LongWord).</summary>
    public const ushort WtldClMaxAuthReasonLen = 0x0006;

    /// <summary>wTLD 0x0007 (SRV_PARAMS_REPLY): Максимальное количество пользовательских/разработческих sTLD (LongWord).</summary>
    public const ushort WtldClMaxUserStldsCount = 0x0007;

    /// <summary>wTLD 0x0008 (SRV_PARAMS_REPLY): Максимальная длина пользовательского/разработческого sTLD (LongWord).</summary>
    public const ushort WtldClMaxUserStldLen = 0x0008;

    /// <summary>wTLD 0x0009 (SRV_PARAMS_REPLY): Количество ожидающих офлайн-сообщений авторизации (LongWord).</summary>
    public const ushort WtldClOfflineAuthCount = 0x0009;

    /// <summary>wTLD 0x000A (SRV_PARAMS_REPLY): Автоудаление флага авторизации после добавления контакта (Bool).</summary>
    public const ushort WtldClAutoRemoveAuthFlag = 0x000A;

    /// <summary>wTLD 0x000B (SRV_PARAMS_REPLY): Максимальное количество заметок (LongWord).</summary>
    public const ushort WtldClMaxNotesCount = 0x000B;

    /// <summary>wTLD 0x000C (SRV_PARAMS_REPLY): Максимальная длина имени заметки в UTF-8 (LongWord).</summary>
    public const ushort WtldClMaxNoteNameLen = 0x000C;

    /// <summary>wTLD 0x000D (SRV_PARAMS_REPLY): Максимальная длина текста заметки в UTF-8 (LongWord).</summary>
    public const ushort WtldClMaxNoteTextLen = 0x000D;

    /// <summary>wTLD 0x0001 (SRV_REPLY): Данные списка контактов в формате BLK blob.</summary>
    public const ushort WtldClContactListData = 0x0001;

    /// <summary>wTLD 0x0001 (SRV_VERIFY_REPLY): MD5-хэш серверного списка контактов (OctaWord).</summary>
    public const ushort WtldClMd5Checksum = 0x0001;

    /// <summary>wTLD 0x0001 (CLI_ADD_ITEM / CLI_UPD_ITEM): Тип элемента списка контактов (Word).</summary>
    public const ushort WtldClItemType = 0x0001;

    /// <summary>wTLD 0x0002 (CLI_ADD_ITEM / CLI_UPD_ITEM): ID родительской группы (LongWord).</summary>
    public const ushort WtldClParentGroupId = 0x0002;

    /// <summary>wTLD 0x0003 (CLI_ADD_ITEM / CLI_UPD_ITEM): Массив sTLD элемента списка контактов.</summary>
    public const ushort WtldClItemStlds = 0x0003;

    /// <summary>wTLD 0x0001 (SRV_ADD_ITEM_REPLY): Код результата добавления (Word).</summary>
    public const ushort WtldClAddResultCode = 0x0001;

    /// <summary>wTLD 0x0002 (SRV_ADD_ITEM_REPLY): ID вновь добавленного элемента (LongWord).</summary>
    public const ushort WtldClNewItemId = 0x0002;

    /// <summary>wTLD 0x0001 (CLI_DEL_ITEM): ID элемента для удаления (LongWord).</summary>
    public const ushort WtldClItemId = 0x0001;

    /// <summary>wTLD 0x0001 (SRV_DEL_ITEM_REPLY): Код результата удаления (Word).</summary>
    public const ushort WtldClDelResultCode = 0x0001;

    /// <summary>wTLD 0x0001 (SRV_UPD_ITEM_REPLY): Код результата операции обновления (Word).</summary>
    public const ushort WtldClUpdResultCode = 0x0001;

    /// <summary>wTLD 0x0001 (AUTH_REQUEST / AUTH_REPLY / AUTH_REVOKE): Имя аккаунта (UTF8).</summary>
    public const ushort WtldClAccountName = 0x0001;

    /// <summary>wTLD 0x0002 (AUTH_REQUEST / AUTH_REVOKE): Причина запроса или отзыва авторизации (UTF8).</summary>
    public const ushort WtldClAuthReason = 0x0002;

    /// <summary>wTLD 0x0003 (AUTH_REQUEST / AUTH_REPLY / AUTH_REVOKE): Флаг офлайн-сообщения авторизации (пустой).</summary>
    public const ushort WtldClOfflineFlag = 0x0003;

    /// <summary>wTLD 0x0004 (AUTH_REQUEST / AUTH_REPLY / AUTH_REVOKE): Время офлайн-сообщения авторизации (DateTime).</summary>
    public const ushort WtldClOfflineTime = 0x0004;

    /// <summary>wTLD 0x0002 (AUTH_REPLY): Код ответа на запрос авторизации (Word).</summary>
    public const ushort WtldClAuthReplyCode = 0x0002;

    /// <summary>wTLD 0x0001 (SRV_ITEM_OPER): Код операции сервера (Word).</summary>
    public const ushort WtldClOperCode = 0x0001;

    /// <summary>wTLD 0x0002 (SRV_ITEM_OPER): Тип элемента списка контактов (Word).</summary>
    public const ushort WtldClOperItemType = 0x0002;

    /// <summary>wTLD 0x0003 (SRV_ITEM_OPER): ID элемента (LongWord).</summary>
    public const ushort WtldClOperItemId = 0x0003;

    /// <summary>wTLD 0x0004 (SRV_ITEM_OPER): ID группы (LongWord).</summary>
    public const ushort WtldClOperGroupId = 0x0004;

    /// <summary>wTLD 0x0005 (SRV_ITEM_OPER): Массив sTLD элемента списка контактов.</summary>
    public const ushort WtldClOperItemStlds = 0x0005;

    // ========================================================================
    // sTLD для элементов списка контактов (BEX 0x0002)
    // ========================================================================

    /// <summary>sTLD 0x0001 (Group): Имя группы (UTF8).</summary>
    public const ushort StldClGroupName = 0x0001;

    /// <summary>sTLD 0x0002 (Contact): Имя аккаунта контакта (UTF8).</summary>
    public const ushort StldClContactAccountName = 0x0002;

    /// <summary>sTLD 0x0003 (Contact): Отображаемое имя контакта (UTF8).</summary>
    public const ushort StldClContactDisplayName = 0x0003;

    /// <summary>sTLD 0x0004 (Contact): Тип приватности (Byte).</summary>
    public const ushort StldClContactPrivacyType = 0x0004;

    /// <summary>sTLD 0x0005 (Contact): Флаг авторизации (пустой).</summary>
    public const ushort StldClContactAuthFlag = 0x0005;

    /// <summary>sTLD 0x0006 (Contact): Флаг общего (системного) элемента (пустой).</summary>
    public const ushort StldClContactGeneralFlag = 0x0006;

    /// <summary>sTLD 0x1001 (Contact): ID элемента транспорта, к которому привязан контакт (LongWord).</summary>
    public const ushort StldClTransportItemId = 0x1001;

    /// <summary>sTLD 0x1002 (Transport): Уникальный UUID транспорта (UUID).</summary>
    public const ushort StldClTransportUuid = 0x1002;

    /// <summary>sTLD 0x1003 (Transport): Имя аккаунта в транспорте (UTF8).</summary>
    public const ushort StldClTransportAccountName = 0x1003;

    /// <summary>sTLD 0x1004 (Transport): Дружественное имя транспорта (UTF8).</summary>
    public const ushort StldClTransportFriendlyName = 0x1004;

    /// <summary>sTLD 0x2001 (Note): Имя заметки (UTF8).</summary>
    public const ushort StldClNoteName = 0x2001;

    /// <summary>sTLD 0x2002 (Note): Тип заметки (Byte).</summary>
    public const ushort StldClNoteType = 0x2002;

    /// <summary>sTLD 0x2003 (Note): Текст заметки (UTF8).</summary>
    public const ushort StldClNoteText = 0x2003;

    /// <summary>sTLD 0x2004 (Note): Дата создания заметки в формате UTC (DateTime).</summary>
    public const ushort StldClNoteDate = 0x2004;

    /// <summary>sTLD 0x2005 (Note): MD5-хэш картинки заметки (OctaWord).</summary>
    public const ushort StldClNotePictureMd5 = 0x2005;

    // ========================================================================
    // wTLD для BEX 0x0003 — Presence
    // ========================================================================

    /// <summary>wTLD 0x0001 (SRV_CONTACT_ONLINE): Имя аккаунта (UTF8).</summary>
    public const ushort WtldPresAccountName = 0x0001;

    /// <summary>wTLD 0x0002 (SRV_CONTACT_ONLINE): Значение статуса присутствия (LongWord).</summary>
    public const ushort WtldPresStatusValue = 0x0002;

    /// <summary>wTLD 0x0003 (SRV_CONTACT_ONLINE): Название пользовательского статуса (UTF8).</summary>
    public const ushort WtldPresStatusName = 0x0003;

    /// <summary>wTLD 0x0004 (SRV_CONTACT_ONLINE): Номер дополнительной картинки статуса (LongWord).</summary>
    public const ushort WtldPresAddPicNumber = 0x0004;

    /// <summary>wTLD 0x0005 (SRV_CONTACT_ONLINE): Описание дополнительной картинки статуса (UTF8).</summary>
    public const ushort WtldPresAddPicDescription = 0x0005;

    /// <summary>wTLD 0x0006 (SRV_CONTACT_ONLINE): Массив возможностей (capabilities) клиента (Word array).</summary>
    public const ushort WtldPresCapabilities = 0x0006;

    /// <summary>wTLD 0x0007 (SRV_CONTACT_ONLINE): Тип клиента (Word).</summary>
    public const ushort WtldPresClientType = 0x0007;

    /// <summary>wTLD 0x0008 (SRV_CONTACT_ONLINE): Название клиента (UTF8).</summary>
    public const ushort WtldPresClientName = 0x0008;

    /// <summary>wTLD 0x0009 (SRV_CONTACT_ONLINE): Версия клиента (QuadWord).</summary>
    public const ushort WtldPresClientVersion = 0x0009;

    /// <summary>wTLD 0x000A (SRV_CONTACT_ONLINE): Время подключения клиента в текущей сессии (DateTime).</summary>
    public const ushort WtldPresConnectedTime = 0x000A;

    /// <summary>wTLD 0x000B (SRV_CONTACT_ONLINE): Дата регистрации аккаунта (DateTime).</summary>
    public const ushort WtldPresRegistrationDate = 0x000B;

    /// <summary>wTLD 0x000C (SRV_CONTACT_ONLINE): MD5-хэш аватара (OctaWord).</summary>
    public const ushort WtldPresAvatarMd5 = 0x000C;

    /// <summary>wTLD 0x000D (SRV_CONTACT_ONLINE): IP-адрес клиента, видимый серверу (UTF8).</summary>
    public const ushort WtldPresClientIp = 0x000D;

    /// <summary>wTLD 0x000E (SRV_CONTACT_ONLINE): UUID дополнительной картинки статуса (UUID).</summary>
    public const ushort WtldPresAddPicId = 0x000E;

    /// <summary>wTLD 0x000F (SRV_CONTACT_ONLINE): Название операционной системы клиента (UTF8).</summary>
    public const ushort WtldPresOsName = 0x000F;

    /// <summary>wTLD 0x0010 (SRV_CONTACT_ONLINE): Дополнительное описание клиента (UTF8).</summary>
    public const ushort WtldPresClientDescription = 0x0010;

    /// <summary>wTLD 0x0011 (SRV_CONTACT_ONLINE): ID пользовательской картинки статуса транспорта (Byte).</summary>
    public const ushort WtldPresCustomTransportStatusPic = 0x0011;

    /// <summary>wTLD 0x0012 (SRV_CONTACT_ONLINE): Массив sTLD идентификации клиента, определённых транспортом (BLK).</summary>
    public const ushort WtldPresTransportStlds = 0x0012;

    /// <summary>wTLD 0x0013 (SRV_CONTACT_ONLINE): Имя хоста клиента (UTF8).</summary>
    public const ushort WtldPresHostName = 0x0013;

    // --- wTLD для CLI_SET_PRES_INFO (Подтип 0x0003) ---
    /// <summary>wTLD 0x0001 (CLI_SET_PRES_INFO): Массив возможностей (capabilities) клиента (Array of Word).</summary>
    public const ushort WtldPresCliCapabilities = 0x0001;

    /// <summary>wTLD 0x0002 (CLI_SET_PRES_INFO): Тип клиента (Word).</summary>
    public const ushort WtldPresCliClientType = 0x0002;

    /// <summary>wTLD 0x0003 (CLI_SET_PRES_INFO): Название клиента (UTF8).</summary>
    public const ushort WtldPresCliClientName = 0x0003;

    /// <summary>wTLD 0x0004 (CLI_SET_PRES_INFO): Версия клиента (QuadWord).</summary>
    public const ushort WtldPresCliClientVersion = 0x0004;

    /// <summary>wTLD 0x0005 (CLI_SET_PRES_INFO): Код языка клиента (Word).</summary>
    public const ushort WtldPresCliLanguageCode = 0x0005;

    // --- wTLD для CLI_SET_STATUS (Подтип 0x0004) ---
    /// <summary>wTLD 0x0001 (CLI_SET_STATUS): Значение статуса присутствия (LongWord).</summary>
    public const ushort WtldPresCliStatusValue = 0x0001;

    // ========================================================================
    // wTLD для BEX 0x0004 — Instant Messaging
    // ========================================================================

    /// <summary>wTLD 0x0001 (SRV_MESSAGE): Имя аккаунта отправителя сообщения (UTF8).</summary>
    public const ushort WtldImSenderAccount = 0x0001;

    /// <summary>wTLD 0x0002 (SRV_MESSAGE): Уникальный ID сообщения (LongWord).</summary>
    public const ushort WtldImMessageId = 0x0002;

    /// <summary>wTLD 0x0003 (SRV_MESSAGE): Тип сообщения (LongWord).</summary>
    public const ushort WtldImMessageType = 0x0003;

    /// <summary>wTLD 0x0004 (SRV_MESSAGE): Данные сообщения (BLK).</summary>
    public const ushort WtldImMessageData = 0x0004;

    /// <summary>wTLD 0x0005 (SRV_MESSAGE): Запрос отчёта о доставке сообщения от удалённого клиента (пустой).</summary>
    public const ushort WtldImReqDeliveryReport = 0x0005;

    /// <summary>wTLD 0x0006 (SRV_MESSAGE): Тип шифрования сообщения (LongWord).</summary>
    public const ushort WtldImEncryptionType = 0x0006;

    /// <summary>wTLD 0x0007 (SRV_MESSAGE): Флаг офлайн-сообщения (пустой).</summary>
    public const ushort WtldImOfflineFlag = 0x0007;

    /// <summary>wTLD 0x0008 (SRV_MESSAGE): Время получения офлайн-сообщения (DateTime).</summary>
    public const ushort WtldImOfflineTime = 0x0008;

    /// <summary>wTLD 0x0009 (SRV_MESSAGE): Флаг системного сообщения (пустой).</summary>
    public const ushort WtldImSystemFlag = 0x0009;

    /// <summary>wTLD 0x000A (SRV_MESSAGE): Позиция всплывающего окна системного сообщения (Byte: 0 - по умолчанию, 1 - центр).</summary>
    public const ushort WtldImSystemPopupPos = 0x000A;

    /// <summary>wTLD 0x000B (SRV_MESSAGE): Флаг множественного сообщения (пустой).</summary>
    public const ushort WtldImMultipleFlag = 0x000B;

    /// <summary>wTLD 0x0001 (MSG_REPORT): Имя аккаунта получателя/отправителя отчёта о доставке (UTF8).</summary>
    public const ushort WtldImReportAccount = 0x0001;

    /// <summary>wTLD 0x0002 (MSG_REPORT): Уникальный ID полученного сообщения, на который дается отчет (LongWord).</summary>
    public const ushort WtldImReportMessageId = 0x0002;

    // --- wTLD для CLI_MESSAGE (Подтип 0x0006) ---
    /// <summary>wTLD 0x0001 (CLI_MESSAGE): Имя аккаунта получателя сообщения (UTF8).</summary>
    public const ushort WtldImReceiverAccount = 0x0001;

    // --- wTLD для CLI_SRV_NOTIFY (Подтип 0x0009) ---
    /// <summary>wTLD 0x0001 (CLI_SRV_NOTIFY): Имя аккаунта получателя/отправителя уведомления (UTF8).</summary>
    public const ushort WtldImNotifyAccount = 0x0001;

    /// <summary>wTLD 0x0002 (CLI_SRV_NOTIFY): Тип уведомления (LongWord).</summary>
    public const ushort WtldImNotifyType = 0x0002;

    /// <summary>wTLD 0x0003 (CLI_SRV_NOTIFY): Значение уведомления (LongWord).</summary>
    public const ushort WtldImNotifyValue = 0x0003;

    // --- Индексы картинок статусов транспортов ---
    /// <summary>Индекс картинки статуса: Логотип транспорта.</summary>
    public const byte ObimpTpStatusIndexLogo = 1;
    /// <summary>Индекс картинки статуса: Онлайн.</summary>
    public const byte ObimpTpStatusIndexOnline = 2;
    /// <summary>Индекс картинки статуса: Офлайн.</summary>
    public const byte ObimpTpStatusIndexOffline = 3;
    /// <summary>Индекс картинки статуса: Подключение.</summary>
    public const byte ObimpTpStatusIndexConnecting = 4;
    /// <summary>Индекс картинки статуса: Не в списке.</summary>
    public const byte ObimpTpStatusIndexNotInList = 5;
    /// <summary>Индекс картинки статуса: Невидимка.</summary>
    public const byte ObimpTpStatusIndexInvisible = 6;
    /// <summary>Индекс картинки статуса: Невидимка для всех.</summary>
    public const byte ObimpTpStatusIndexInvisibleForAll = 7;
    /// <summary>Индекс картинки статуса: Отошел.</summary>
    public const byte ObimpTpStatusIndexAway = 8;
    /// <summary>Индекс картинки статуса: Недоступен.</summary>
    public const byte ObimpTpStatusIndexNotAvailable = 9;
    /// <summary>Индекс картинки статуса: Занят.</summary>
    public const byte ObimpTpStatusIndexOccupied = 10;
    /// <summary>Индекс картинки статуса: Не беспокоить.</summary>
    public const byte ObimpTpStatusIndexDoNotDisturb = 11;
    /// <summary>Индекс картинки статуса: Обед.</summary>
    public const byte ObimpTpStatusIndexLunch = 12;
    /// <summary>Индекс картинки статуса: Дома.</summary>
    public const byte ObimpTpStatusIndexAtHome = 13;
    /// <summary>Индекс картинки статуса: На работе.</summary>
    public const byte ObimpTpStatusIndexAtWork = 14;
    /// <summary>Индекс картинки статуса: Свободен для общения.</summary>
    public const byte ObimpTpStatusIndexFreeForChat = 15;

    // ========================================================================
    // UUID дополнительных статусов (Section 4)
    // ========================================================================
    /// <summary>UUID дополнительной картинки статуса: Улыбка.</summary>
    public const string AddStatusPicUuidSmile = "10790001-3AE3-4779-0034-340000000001";
    /// <summary>UUID дополнительной картинки статуса: Пляж.</summary>
    public const string AddStatusPicUuidBeach = "10790001-3AE3-4779-0034-340000000002";
    /// <summary>UUID дополнительной картинки статуса: Коктейль.</summary>
    public const string AddStatusPicUuidCocktail = "10790001-3AE3-4779-0034-340000000003";
    /// <summary>UUID дополнительной картинки статуса: Спасательный круг.</summary>
    public const string AddStatusPicUuidLifebuoy = "10790001-3AE3-4779-0034-340000000004";
    /// <summary>UUID дополнительной картинки статуса: Уборка.</summary>
    public const string AddStatusPicUuidCleaning = "10790001-3AE3-4779-0034-340000000005";
    /// <summary>UUID дополнительной картинки статуса: Готовка.</summary>
    public const string AddStatusPicUuidCooking = "10790001-3AE3-4779-0034-340000000006";
    /// <summary>UUID дополнительной картинки статуса: Вечеринка.</summary>
    public const string AddStatusPicUuidParty = "10790001-3AE3-4779-0034-340000000007";
    /// <summary>UUID дополнительной картинки статуса: Размышление.</summary>
    public const string AddStatusPicUuidThinking = "10790001-3AE3-4779-0034-340000000008";
    /// <summary>UUID дополнительной картинки статуса: Обед.</summary>
    public const string AddStatusPicUuidLunch = "10790001-3AE3-4779-0034-340000000009";
    /// <summary>UUID дополнительной картинки статуса: Телевизор.</summary>
    public const string AddStatusPicUuidTv = "10790001-3AE3-4779-0034-34000000000A";
    /// <summary>UUID дополнительной картинки статуса: Друзья.</summary>
    public const string AddStatusPicUuidFriends = "10790001-3AE3-4779-0034-34000000000B";
    /// <summary>UUID дополнительной картинки статуса: Кофе.</summary>
    public const string AddStatusPicUuidCoffee = "10790001-3AE3-4779-0034-34000000000C";
    /// <summary>UUID дополнительной картинки статуса: Музыка.</summary>
    public const string AddStatusPicUuidMusic = "10790001-3AE3-4779-0034-34000000000D";
    /// <summary>UUID дополнительной картинки статуса: Бизнес.</summary>
    public const string AddStatusPicUuidBusiness = "10790001-3AE3-4779-0034-34000000000E";
    /// <summary>UUID дополнительной картинки статуса: Камера.</summary>
    public const string AddStatusPicUuidCamera = "10790001-3AE3-4779-0034-34000000000F";
    /// <summary>UUID дополнительной картинки статуса: Язык.</summary>
    public const string AddStatusPicUuidTongue = "10790001-3AE3-4779-0034-340000000010";
    /// <summary>UUID дополнительной картинки статуса: Телефон.</summary>
    public const string AddStatusPicUuidPhone = "10790001-3AE3-4779-0034-340000000011";
    /// <summary>UUID дополнительной картинки статуса: Игры.</summary>
    public const string AddStatusPicUuidGaming = "10790001-3AE3-4779-0034-340000000012";
    /// <summary>UUID дополнительной картинки статуса: Учёба.</summary>
    public const string AddStatusPicUuidStudy = "10790001-3AE3-4779-0034-340000000013";
    /// <summary>UUID дополнительной картинки статуса: Шопинг.</summary>
    public const string AddStatusPicUuidShopping = "10790001-3AE3-4779-0034-340000000014";
    /// <summary>UUID дополнительной картинки статуса: Автомобиль.</summary>
    public const string AddStatusPicUuidCar = "10790001-3AE3-4779-0034-340000000015";
    /// <summary>UUID дополнительной картинки статуса: Болезнь.</summary>
    public const string AddStatusPicUuidIll = "10790001-3AE3-4779-0034-340000000016";
    /// <summary>UUID дополнительной картинки статуса: Сон.</summary>
    public const string AddStatusPicUuidSleeping = "10790001-3AE3-4779-0034-340000000017";
    /// <summary>UUID дополнительной картинки статуса: Серфинг в интернете.</summary>
    public const string AddStatusPicUuidBrowsing = "10790001-3AE3-4779-0034-340000000018";
    /// <summary>UUID дополнительной картинки статуса: Работа.</summary>
    public const string AddStatusPicUuidWorking = "10790001-3AE3-4779-0034-340000000019";
    /// <summary>UUID дополнительной картинки статуса: Письмо.</summary>
    public const string AddStatusPicUuidWriting = "10790001-3AE3-4779-0034-34000000001A";
    /// <summary>UUID дополнительной картинки статуса: Пикник.</summary>
    public const string AddStatusPicUuidPicnic = "10790001-3AE3-4779-0034-34000000001B";
    /// <summary>UUID дополнительной картинки статуса: Спорт.</summary>
    public const string AddStatusPicUuidSport = "10790001-3AE3-4779-0034-34000000001C";
    /// <summary>UUID дополнительной картинки статуса: Мобильный.</summary>
    public const string AddStatusPicUuidMobile = "10790001-3AE3-4779-0034-34000000001D";
    /// <summary>UUID дополнительной картинки статуса: Грусть.</summary>
    public const string AddStatusPicUuidSad = "10790001-3AE3-4779-0034-34000000001E";
    /// <summary>UUID дополнительной картинки статуса: Туалет.</summary>
    public const string AddStatusPicUuidWc = "10790001-3AE3-4779-0034-34000000001F";
    /// <summary>UUID дополнительной картинки статуса: Вопрос.</summary>
    public const string AddStatusPicUuidQuestion = "10790001-3AE3-4779-0034-340000000020";
    /// <summary>UUID дополнительной картинки статуса: Звук.</summary>
    public const string AddStatusPicUuidSound = "10790001-3AE3-4779-0034-340000000021";
    /// <summary>UUID дополнительной картинки статуса: Сердце.</summary>
    public const string AddStatusPicUuidHeart = "10790001-3AE3-4779-0034-340000000022";
    /// <summary>UUID дополнительной картинки статуса: Охота.</summary>
    public const string AddStatusPicUuidHunting = "10790001-3AE3-4779-0034-340000000023";
    /// <summary>UUID дополнительной картинки статуса: Поиск.</summary>
    public const string AddStatusPicUuidSearching = "10790001-3AE3-4779-0034-340000000024";
    /// <summary>UUID дополнительной картинки статуса: Дневник.</summary>
    public const string AddStatusPicUuidJournal = "10790001-3AE3-4779-0034-340000000025";
    /// <summary>UUID дополнительной картинки статуса: Звезда.</summary>
    public const string AddStatusPicUuidStar = "10790001-3AE3-4779-0034-340000000026";
    /// <summary>UUID дополнительной картинки статуса: Рисование.</summary>
    public const string AddStatusPicUuidPainting = "10790001-3AE3-4779-0034-340000000027";
    /// <summary>UUID дополнительной картинки статуса: Душ.</summary>
    public const string AddStatusPicUuidShower = "10790001-3AE3-4779-0034-340000000028";
    /// <summary>UUID дополнительной картинки статуса: Природа.</summary>
    public const string AddStatusPicUuidNature = "10790001-3AE3-4779-0034-340000000029";
    /// <summary>UUID дополнительной картинки статуса: Идея.</summary>
    public const string AddStatusPicUuidIdea = "10790001-3AE3-4779-0034-34000000002A";
    /// <summary>UUID дополнительной картинки статуса: Деньги.</summary>
    public const string AddStatusPicUuidMoney = "10790001-3AE3-4779-0034-34000000002B";
    /// <summary>UUID дополнительной картинки статуса: Чтение.</summary>
    public const string AddStatusPicUuidReading = "10790001-3AE3-4779-0034-34000000002C";
    /// <summary>UUID дополнительной картинки статуса: Химия.</summary>
    public const string AddStatusPicUuidChemical = "10790001-3AE3-4779-0034-34000000002D";
    /// <summary>UUID дополнительной картинки статуса: Солнце.</summary>
    public const string AddStatusPicUuidSun = "10790001-3AE3-4779-0034-34000000002E";
    /// <summary>UUID дополнительной картинки статуса: Снег.</summary>
    public const string AddStatusPicUuidSnow = "10790001-3AE3-4779-0034-34000000002F";
    /// <summary>UUID дополнительной картинки статуса: Ремонт.</summary>
    public const string AddStatusPicUuidFixing = "10790001-3AE3-4779-0034-340000000030";
    /// <summary>UUID дополнительной картинки статуса: Палец вверх.</summary>
    public const string AddStatusPicUuidThumbsUp = "10790001-3AE3-4779-0034-340000000031";
    /// <summary>UUID дополнительной картинки статуса: Шок.</summary>
    public const string AddStatusPicUuidShocked = "10790001-3AE3-4779-0034-340000000032";
    /// <summary>UUID дополнительной картинки статуса: Планета.</summary>
    public const string AddStatusPicUuidPlanet = "10790001-3AE3-4779-0034-340000000033";
    /// <summary>UUID дополнительной картинки статуса: Напиток.</summary>
    public const string AddStatusPicUuidDrink = "10790001-3AE3-4779-0034-340000000034";
    /// <summary>UUID дополнительной картинки статуса: Злость.</summary>
    public const string AddStatusPicUuidAngry = "10790001-3AE3-4779-0034-340000000035";
    /// <summary>UUID дополнительной картинки статуса: Усталость.</summary>
    public const string AddStatusPicUuidTired = "10790001-3AE3-4779-0034-340000000036";
    /// <summary>UUID дополнительной картинки статуса: Курение.</summary>
    public const string AddStatusPicUuidSmoke = "10790001-3AE3-4779-0034-340000000037";
}

/// <summary>
/// Коды ответа на запрос авторизации.
/// Используется в BEX 0x0002, подтип 0x000E (SRV_AUTH_REPLY), wTLD 0x0002.
/// </summary>
public enum AuthReplyCode : ushort
{
    /// <summary>Авторизация одобрена — сервер автоматически уберёт флаг авторизации и начнет рассылку статусов.</summary>
    Granted = 0x0001,
    /// <summary>Авторизация отклонена — клиенту следует удалить контакт или повторить запрос позже.</summary>
    Denied = 0x0002
}

/// <summary>
/// Коды стран согласно спецификации OBIMP (Section 5).
/// </summary>
public enum CountryCode : ushort
{
    /// <summary>Афганистан</summary> Afghanistan = 1,
    /// <summary>Албания</summary> Albania = 2,
    /// <summary>Антарктида</summary> Antarctica = 3,
    /// <summary>Алжир</summary> Algeria = 4,
    /// <summary>Американское Самоа</summary> AmericanSamoa = 5,
    /// <summary>Андорра</summary> Andorra = 6,
    /// <summary>Ангола</summary> Angola = 7,
    /// <summary>Антигуа и Барбуда</summary> AntiguaAndBarbuda = 8,
    /// <summary>Азербайджан</summary> Azerbaijan = 9,
    /// <summary>Аргентина</summary> Argentina = 10,
    /// <summary>Австралия</summary> Australia = 11,
    /// <summary>Австрия</summary> Austria = 12,
    /// <summary>Багамы</summary> Bahamas = 13,
    /// <summary>Бахрейн</summary> Bahrain = 14,
    /// <summary>Бангладеш</summary> Bangladesh = 15,
    /// <summary>Армения</summary> Armenia = 16,
    /// <summary>Барбадос</summary> Barbados = 17,
    /// <summary>Бельгия</summary> Belgium = 18,
    /// <summary>Бермуды</summary> Bermuda = 19,
    /// <summary>Бутан</summary> Bhutan = 20,
    /// <summary>Боливия</summary> Bolivia = 21,
    /// <summary>Босния и Герцеговина</summary> BosniaAndHerzegovina = 22,
    /// <summary>Ботсвана</summary> Botswana = 23,
    /// <summary>Остров Буве</summary> BouvetIsland = 24,
    /// <summary>Бразилия</summary> Brazil = 25,
    /// <summary>Белиз</summary> Belize = 26,
    /// <summary>Британская территория в Индийском океане</summary> BritishIndianOceanTerritory = 27,
    /// <summary>Соломоновы Острова</summary> SolomonIslands = 28,
    /// <summary>Виргинские Острова (Британские)</summary> VirginIslandsBritish = 29,
    /// <summary>Бруней</summary> BruneiDarussalam = 30,
    /// <summary>Болгария</summary> Bulgaria = 31,
    /// <summary>Мьянма</summary> Myanmar = 32,
    /// <summary>Бурунди</summary> Burundi = 33,
    /// <summary>Беларусь</summary> Belarus = 34,
    /// <summary>Камбоджа</summary> Cambodia = 35,
    /// <summary>Камерун</summary> Cameroon = 36,
    /// <summary>Канада</summary> Canada = 37,
    /// <summary>Кабо-Верде</summary> CapeVerde = 38,
    /// <summary>Каймановы Острова</summary> CaymanIslands = 39,
    /// <summary>Центральноафриканская Республика</summary> CentralAfricanRepublic = 40,
    /// <summary>Шри-Ланка</summary> SriLanka = 41,
    /// <summary>Чад</summary> Chad = 42,
    /// <summary>Чили</summary> Chile = 43,
    /// <summary>Китай</summary> China = 44,
    /// <summary>Тайвань</summary> Taiwan = 45,
    /// <summary>Остров Рождества</summary> ChristmasIsland = 46,
    /// <summary>Кокосовые Острова</summary> CocosIslands = 47,
    /// <summary>Колумбия</summary> Colombia = 48,
    /// <summary>Коморы</summary> Comoros = 49,
    /// <summary>Майотта</summary> Mayotte = 50,
    /// <summary>Конго</summary> Congo = 51,
    /// <summary>Демократическая Республика Конго</summary> CongoDemocratic = 52,
    /// <summary>Острова Кука</summary> CookIslands = 53,
    /// <summary>Коста-Рика</summary> CostaRica = 54,
    /// <summary>Хорватия</summary> Croatia = 55,
    /// <summary>Куба</summary> Cuba = 56,
    /// <summary>Кипр</summary> Cyprus = 57,
    /// <summary>Чехия</summary> CzechRepublic = 58,
    /// <summary>Бенин</summary> Benin = 59,
    /// <summary>Дания</summary> Denmark = 60,
    /// <summary>Доминика</summary> Dominica = 61,
    /// <summary>Доминиканская Республика</summary> DominicanRepublic = 62,
    /// <summary>Эквадор</summary> Ecuador = 63,
    /// <summary>Сальвадор</summary> ElSalvador = 64,
    /// <summary>Экваториальная Гвинея</summary> EquatorialGuinea = 65,
    /// <summary>Эфиопия</summary> Ethiopia = 66,
    /// <summary>Эритрея</summary> Eritrea = 67,
    /// <summary>Эстония</summary> Estonia = 68,
    /// <summary>Фарерские Острова</summary> FaroeIslands = 69,
    /// <summary>Фолклендские Острова</summary> FalklandIslands = 70,
    /// <summary>Южная Георгия и Южные Сандвичевы Острова</summary> SouthGeorgia = 71,
    /// <summary>Фиджи</summary> Fiji = 72,
    /// <summary>Финляндия</summary> Finland = 73,
    /// <summary>Аландские Острова</summary> AlandIslands = 74,
    /// <summary>Франция</summary> France = 75,
    /// <summary>Французская Гвиана</summary> FrenchGuiana = 76,
    /// <summary>Французская Полинезия</summary> FrenchPolynesia = 77,
    /// <summary>Французские Южные Территории</summary> FrenchSouthernTerritories = 78,
    /// <summary>Джибути</summary> Djibouti = 79,
    /// <summary>Габон</summary> Gabon = 80,
    /// <summary>Грузия</summary> Georgia = 81,
    /// <summary>Гамбия</summary> Gambia = 82,
    /// <summary>Палестина</summary> PalestinianTerritory = 83,
    /// <summary>Германия</summary> Germany = 84,
    /// <summary>Гана</summary> Ghana = 85,
    /// <summary>Гибралтар</summary> Gibraltar = 86,
    /// <summary>Кирибати</summary> Kiribati = 87,
    /// <summary>Греция</summary> Greece = 88,
    /// <summary>Гренландия</summary> Greenland = 89,
    /// <summary>Гренада</summary> Grenada = 90,
    /// <summary>Гваделупа</summary> Guadeloupe = 91,
    /// <summary>Гуам</summary> Guam = 92,
    /// <summary>Гватемала</summary> Guatemala = 93,
    /// <summary>Гвинея</summary> Guinea = 94,
    /// <summary>Гайана</summary> Guyana = 95,
    /// <summary>Гаити</summary> Haiti = 96,
    /// <summary>Херд и Макдональд</summary> HeardIsland = 97,
    /// <summary>Ватикан</summary> HolySee = 98,
    /// <summary>Гондурас</summary> Honduras = 99,
    /// <summary>Гонконг</summary> HongKong = 100,
    /// <summary>Венгрия</summary> Hungary = 101,
    /// <summary>Исландия</summary> Iceland = 102,
    /// <summary>Индия</summary> India = 103,
    /// <summary>Индонезия</summary> Indonesia = 104,
    /// <summary>Иран</summary> Iran = 105,
    /// <summary>Ирак</summary> Iraq = 106,
    /// <summary>Ирландия</summary> Ireland = 107,
    /// <summary>Израиль</summary> Israel = 108,
    /// <summary>Италия</summary> Italy = 109,
    /// <summary>Кот-д'Ивуар</summary> CoteDIvoire = 110,
    /// <summary>Ямайка</summary> Jamaica = 111,
    /// <summary>Япония</summary> Japan = 112,
    /// <summary>Казахстан</summary> Kazakhstan = 113,
    /// <summary>Иордания</summary> Jordan = 114,
    /// <summary>Кения</summary> Kenya = 115,
    /// <summary>КНДР</summary> KoreaDPR = 116,
    /// <summary>Республика Корея</summary> KoreaRepublic = 117,
    /// <summary>Кувейт</summary> Kuwait = 118,
    /// <summary>Кыргызстан</summary> Kyrgyzstan = 119,
    /// <summary>Лаос</summary> Lao = 120,
    /// <summary>Ливан</summary> Lebanon = 121,
    /// <summary>Лесото</summary> Lesotho = 122,
    /// <summary>Латвия</summary> Latvia = 123,
    /// <summary>Либерия</summary> Liberia = 124,
    /// <summary>Ливия</summary> Libya = 125,
    /// <summary>Лихтенштейн</summary> Liechtenstein = 126,
    /// <summary>Литва</summary> Lithuania = 127,
    /// <summary>Люксембург</summary> Luxembourg = 128,
    /// <summary>Макао</summary> Macao = 129,
    /// <summary>Мадагаскар</summary> Madagascar = 130,
    /// <summary>Малави</summary> Malawi = 131,
    /// <summary>Малайзия</summary> Malaysia = 132,
    /// <summary>Мальдивы</summary> Maldives = 133,
    /// <summary>Мали</summary> Mali = 134,
    /// <summary>Мальта</summary> Malta = 135,
    /// <summary>Мартиника</summary> Martinique = 136,
    /// <summary>Мавритания</summary> Mauritania = 137,
    /// <summary>Маврикий</summary> Mauritius = 138,
    /// <summary>Мексика</summary> Mexico = 139,
    /// <summary>Монако</summary> Monaco = 140,
    /// <summary>Монголия</summary> Mongolia = 141,
    /// <summary>Молдова</summary> Moldova = 142,
    /// <summary>Черногория</summary> Montenegro = 143,
    /// <summary>Монтсеррат</summary> Montserrat = 144,
    /// <summary>Марокко</summary> Morocco = 145,
    /// <summary>Мозамбик</summary> Mozambique = 146,
    /// <summary>Оман</summary> Oman = 147,
    /// <summary>Намибия</summary> Namibia = 148,
    /// <summary>Науру</summary> Nauru = 149,
    /// <summary>Непал</summary> Nepal = 150,
    /// <summary>Нидерланды</summary> Netherlands = 151,
    /// <summary>Нидерландские Антильские Острова</summary> NetherlandsAntilles = 152,
    /// <summary>Аруба</summary> Aruba = 153,
    /// <summary>Новая Каледония</summary> NewCaledonia = 154,
    /// <summary>Вануату</summary> Vanuatu = 155,
    /// <summary>Новая Зеландия</summary> NewZealand = 156,
    /// <summary>Никарагуа</summary> Nicaragua = 157,
    /// <summary>Нигер</summary> Niger = 158,
    /// <summary>Нигерия</summary> Nigeria = 159,
    /// <summary>Ниуэ</summary> Niue = 160,
    /// <summary>Остров Норфолк</summary> NorfolkIsland = 161,
    /// <summary>Норвегия</summary> Norway = 162,
    /// <summary>Северные Марианские Острова</summary> NorthernMarianaIslands = 163,
    /// <summary>Малые Тихоокеанские Отдаленные Острова США</summary> USMinorOutlyingIslands = 164,
    /// <summary>Микронезия</summary> Micronesia = 165,
    /// <summary>Маршалловы Острова</summary> MarshallIslands = 166,
    /// <summary>Палау</summary> Palau = 167,
    /// <summary>Пакистан</summary> Pakistan = 168,
    /// <summary>Панама</summary> Panama = 169,
    /// <summary>Папуа — Новая Гвинея</summary> PapuaNewGuinea = 170,
    /// <summary>Парагвай</summary> Paraguay = 171,
    /// <summary>Перу</summary> Peru = 172,
    /// <summary>Филиппины</summary> Philippines = 173,
    /// <summary>Питкэрн</summary> Pitcairn = 174,
    /// <summary>Польша</summary> Poland = 175,
    /// <summary>Португалия</summary> Portugal = 176,
    /// <summary>Гвинея-Бисау</summary> GuineaBissau = 177,
    /// <summary>Восточный Тимор</summary> TimorLeste = 178,
    /// <summary>Пуэрто-Рико</summary> PuertoRico = 179,
    /// <summary>Катар</summary> Qatar = 180,
    /// <summary>Реюньон</summary> Reunion = 181,
    /// <summary>Румыния</summary> Romania = 182,
    /// <summary>Россия</summary> 
         RussianFederation = 183,
    /// <summary>Руанда</summary> Rwanda = 184,
    /// <summary>Сен-Бартелеми</summary> SaintBarthelemy = 185,
    /// <summary>Остров Святой Елены</summary> SaintHelena = 186,
    /// <summary>Сент-Китс и Невис</summary> SaintKittsAndNevis = 187,
    /// <summary>Ангилья</summary> Anguilla = 188,
    /// <summary>Сент-Люсия</summary> SaintLucia = 189,
    /// <summary>Сен-Мартен</summary> SaintMartin = 190,
    /// <summary>Сен-Пьер и Микелон</summary> SaintPierreAndMiquelon = 191,
    /// <summary>Сент-Винсент и Гренадины</summary> SaintVincentAndTheGrenadines = 192,
    /// <summary>Сан-Марино</summary> SanMarino = 193,
    /// <summary>Сан-Томе и Принсипи</summary> SaoTomeAndPrincipe = 194,
    /// <summary>Саудовская Аравия</summary> SaudiArabia = 195,
    /// <summary>Сенегал</summary> Senegal = 196,
    /// <summary>Сербия</summary> Serbia = 197,
    /// <summary>Сейшельские Острова</summary> Seychelles = 198,
    /// <summary>Сьерра-Леоне</summary> SierraLeone = 199,
    /// <summary>Сингапур</summary> Singapore = 200,
    /// <summary>Словакия</summary> Slovakia = 201,
    /// <summary>Вьетнам</summary> VietNam = 202,
    /// <summary>Словения</summary> Slovenia = 203,
    /// <summary>Сомали</summary> Somalia = 204,
    /// <summary>ЮАР</summary> SouthAfrica = 205,
    /// <summary>Зимбабве</summary> Zimbabwe = 206,
    /// <summary>Испания</summary> Spain = 207,
    /// <summary>Западная Сахара</summary> WesternSahara = 208,
    /// <summary>Судан</summary> Sudan = 209,
    /// <summary>Суринам</summary> Suriname = 210,
    /// <summary>Шпицберген и Ян-Майен</summary> SvalbardAndJanMayen = 211,
    /// <summary>Эсватини</summary> Swaziland = 212,
    /// <summary>Швеция</summary> Sweden = 213,
    /// <summary>Швейцария</summary> Switzerland = 214,
    /// <summary>Сирия</summary> SyrianArabRepublic = 215,
    /// <summary>Таджикистан</summary> Tajikistan = 216,
    /// <summary>Таиланд</summary> Thailand = 217,
    /// <summary>Того</summary> Togo = 218,
    /// <summary>Токелау</summary> Tokelau = 219,
    /// <summary>Тонга</summary> Tonga = 220,
    /// <summary>Тринидад и Тобаго</summary> TrinidadAndTobago = 221,
    /// <summary>ОАЭ</summary> UnitedArabEmirates = 222,
    /// <summary>Тунис</summary> Tunisia = 223,
    /// <summary>Турция</summary> Turkey = 224,
    /// <summary>Туркменистан</summary> Turkmenistan = 225,
    /// <summary>Теркс и Кайкос</summary> TurksAndCaicosIslands = 226,
    /// <summary>Тувалу</summary> Tuvalu = 227,
    /// <summary>Уганда</summary> Uganda = 228,
    /// <summary>Украина</summary> Ukraine = 229,
    /// <summary>Северная Македония</summary> Macedonia = 230,
    /// <summary>Египет</summary> Egypt = 231,
    /// <summary>Великобритания</summary> UnitedKingdom = 232,
    /// <summary>Гернси</summary> Guernsey = 233,
    /// <summary>Джерси</summary> Jersey = 234,
    /// <summary>Остров Мэн</summary> IsleOfMan = 235,
    /// <summary>Танзания</summary> Tanzania = 236,
    /// <summary>США</summary> UnitedStates = 237,
    /// <summary>Виргинские Острова (США)</summary> VirginIslandsUS = 238,
    /// <summary>Буркина-Фасо</summary> BurkinaFaso = 239,
    /// <summary>Уругвай</summary> Uruguay = 240,
    /// <summary>Узбекистан</summary> Uzbekistan = 241,
    /// <summary>Венесуэла</summary> Venezuela = 242,
    /// <summary>Уоллис и Футуна</summary> WallisAndFutuna = 243,
    /// <summary>Самоа</summary> Samoa = 244,
    /// <summary>Йемен</summary> Yemen = 245,
    /// <summary>Замбия</summary> Zambia = 246
}

/// <summary>
/// Коды языков согласно спецификации OBIMP (Section 5).
/// </summary>
public enum LanguageCode : ushort
{
    /// <summary>Африкаанс</summary> Afrikaans = 1,
    /// <summary>Албанский</summary> Albanian = 2,
    /// <summary>Арабский</summary> Arabic = 3,
    /// <summary>Армянский</summary> Armenian = 4,
    /// <summary>Азербайджанский</summary> Azerbaijani = 5,
    /// <summary>Белорусский</summary> Belorussian = 6,
    /// <summary>Бходжпури</summary> Bhojpuri = 7,
    /// <summary>Боснийский</summary> Bosnian = 8,
    /// <summary>Болгарский</summary> Bulgarian = 9,
    /// <summary>Бирманский</summary> Burmese = 10,
    /// <summary>Кантонский</summary> Cantonese = 11,
    /// <summary>Каталанский</summary> Catalan = 12,
    /// <summary>Чаморро</summary> Chamorro = 13,
    /// <summary>Китайский</summary> Chinese = 14,
    /// <summary>Хорватский</summary> Croatian = 15,
    /// <summary>Чешский</summary> Czech = 16,
    /// <summary>Датский</summary> Danish = 17,
    /// <summary>Голландский</summary> Dutch = 18,
    /// <summary>Английский</summary> English = 19,
    /// <summary>Эсперанто</summary> Esperanto = 20,
    /// <summary>Эстонский</summary> Estonian = 21,
    /// <summary>Персидский (Фарси)</summary> Farsi = 22,
    /// <summary>Финский</summary> Finnish = 23,
    /// <summary>Французский</summary> French = 24,
    /// <summary>Гэльский</summary> Gaelic = 25,
    /// <summary>Немецкий</summary> German = 26,
    /// <summary>Греческий</summary> Greek = 27,
    /// <summary>Гуджарати</summary> Gujarati = 28,
    /// <summary>Иврит</summary> Hebrew = 29,
    /// <summary>Хинди</summary> Hindi = 30,
    /// <summary>Венгерский</summary> Hungarian = 31,
    /// <summary>Исландский</summary> Icelandic = 32,
    /// <summary>Индонезийский</summary> Indonesian = 33,
    /// <summary>Итальянский</summary> Italian = 34,
    /// <summary>Японский</summary> Japanese = 35,
    /// <summary>Кхмерский</summary> Khmer = 36,
    /// <summary>Корейский</summary> Korean = 37,
    /// <summary>Курдский</summary> Kurdish = 38,
    /// <summary>Лаосский</summary> Lao = 39,
    /// <summary>Латышский</summary> Latvian = 40,
    /// <summary>Литовский</summary> Lithuanian = 41,
    /// <summary>Македонский</summary> Macedonian = 42,
    /// <summary>Малайский</summary> Malay = 43,
    /// <summary>Мандарин</summary> Mandarin = 44,
    /// <summary>Монгольский</summary> Mongolian = 45,
    /// <summary>Норвежский</summary> Norwegian = 46,
    /// <summary>Персидский</summary> Persian = 47,
    /// <summary>Польский</summary> Polish = 48,
    /// <summary>Португальский</summary> Portuguese = 49,
    /// <summary>Пенджабский</summary> Punjabi = 50,
    /// <summary>Румынский</summary> Romanian = 51,
    /// <summary>Русский</summary> 
         Russian = 52,
    /// <summary>Сербский</summary> Serbian = 53,
    /// <summary>Синдхи</summary> Sindhi = 54,
    /// <summary>Словацкий</summary> Slovak = 55,
    /// <summary>Словенский</summary> Slovenian = 56,
    /// <summary>Сомалийский</summary> Somali = 57,
    /// <summary>Испанский</summary> Spanish = 58,
    /// <summary>Суахили</summary> Swahili = 59,
    /// <summary>Шведский</summary> Swedish = 60,
    /// <summary>Тагальский</summary> Tagalog = 61,
    /// <summary>Тайваньский</summary> Taiwanese = 62,
    /// <summary>Тамильский</summary> Tamil = 63,
    /// <summary>Татарский</summary> Tatar = 64,
    /// <summary>Тайский</summary> Thai = 65,
    /// <summary>Турецкий</summary> Turkish = 66,
    /// <summary>Украинский</summary> Ukrainian = 67,
    /// <summary>Урду</summary> Urdu = 68,
    /// <summary>Вьетнамский</summary> Vietnamese = 69,
    /// <summary>Валлийский</summary> Welsh = 70,
    /// <summary>Идиш</summary> Yiddish = 71,
    /// <summary>Йоруба</summary> Yoruba = 72,
    /// <summary>Казахский</summary> Kazakh = 73,
    /// <summary>Киргизский</summary> Kyrgyz = 74,
    /// <summary>Таджикский</summary> Tajik = 75,
    /// <summary>Туркменский</summary> Turkmen = 76,
    /// <summary>Узбекский</summary> Uzbek = 77,
    /// <summary>Грузинский</summary> Georgian = 78
}
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace OBIMPClient.Security;

// ========================================================================
// PasswordHasher — алгоритм хеширования пароля для авторизации OBIMP
// ========================================================================

/// <summary>
/// Статический класс, реализующий алгоритм MD5-хеширования пароля для входа в OBIMP.
/// 
/// Формула хеширования (согласно спецификации OBIMP):
/// 
///   Hash = MD5( InnerHash + ServerKey )
///   где InnerHash = MD5( LowerCase(Account) + "OBIMPSALT" + Password )
/// 
/// Алгоритм выполняется в два шага:
/// 
///   1. Внутренний хэш (Inner Hash):
///      - Имя аккаунта переводится в нижний регистр
///      - Конкатенация: LowerCase(Account) + "OBIMPSALT" + Password
///      - Вычисляется MD5 от конкатенированной строки
/// 
///   2. Внешний хэш (Outer Hash):
///      - Конкатенация: InnerHash (16 байт) + ServerKey (получен от сервера в SRV_HELLO wTLD 0x0002)
///      - Вычисляется MD5 от конкатенированного массива байт
/// 
/// Результат — 16-байтовый MD5-хэш, который передаётся серверу в CLI_LOGIN (BEX 0x0001, subtype 0x0003)
/// в wTLD 0x0002 как OctaWord (8 байт? Нет — 16 байт, так как MD5 всегда 16 байт).
/// 
/// Этапы входа в систему:
///   1. CLI_HELLO (account name) → SRV_HELLO (ServerKey в wTLD 0x0002)
///   2. PasswordHasher.GenerateHash(account, password, serverKey) → MD5-хэш
///   3. CLI_LOGIN (account name + MD5-хэш) → SRV_LOGIN_REPLY
/// 
/// Альтернативный сценарий (plain-text):
///   SRV_HELLO может содержать wTLD 0x0007 (пустой) — сервер требует plain-text пароль.
///   В этом случае CLI_LOGIN содержит wTLD 0x0003 с паролем в открытом виде.
/// </summary>
public static class PasswordHasher
{
    /// <summary>
    /// Фиксированная соль ("OBIMPSALT"), используемая во внутреннем хэше.
    /// Значение определено спецификацией OBIMP и не может быть изменено.
    /// </summary>
    private const string Salt = "OBIMPSALT";

    /// <summary>
    /// Генерирует MD5-хэш пароля для авторизации в OBIMP.
    /// 
    /// Алгоритм:
    ///   1. Inner = MD5( UTF8(LowerCase(Account)) + UTF8("OBIMPSALT") + UTF8(Password) )
    ///   2. Outer = MD5( Inner + ServerKey )
    ///   3. Возвращается Outer (16 байт).
    /// 
    /// </summary>
    /// <param name="account">Имя аккаунта (учётной записи). Переводится в нижний регистр перед хешированием.</param>
    /// <param name="password">Пароль пользователя в открытом виде.</param>
    /// <param name="serverKey">
    /// Серверный ключ (Server Key), полученный от сервера в SRV_HELLO (BEX 0x0001, subtype 0x0002, wTLD 0x0002).
    /// Используется во внешнем хэше для формирования одноразового хэша.
    /// </param>
    /// <returns>16-байтовый MD5-хэш, готовый для передачи в CLI_LOGIN (wTLD 0x0002).</returns>
    public static byte[] GenerateHash(string account, string password, byte[] serverKey)
    {
        // Шаг 1: переводим имя аккаунта в нижний регистр
        var lowerAccount = account.ToLower();

        // Шаг 2: кодируем все компоненты в UTF-8
        var acctBytes = Encoding.UTF8.GetBytes(lowerAccount);
        var saltBytes = Encoding.UTF8.GetBytes(Salt);
        var passBytes = Encoding.UTF8.GetBytes(password);

        // Шаг 3: вычисляем внутренний хэш
        using var md5 = MD5.Create();
        var inner = new byte[acctBytes.Length + saltBytes.Length + passBytes.Length];
        Buffer.BlockCopy(acctBytes, 0, inner, 0, acctBytes.Length);
        Buffer.BlockCopy(saltBytes, 0, inner, acctBytes.Length, saltBytes.Length);
        Buffer.BlockCopy(passBytes, 0, inner, acctBytes.Length + saltBytes.Length, passBytes.Length);

        var innerHash = md5.ComputeHash(inner);

        // Шаг 4: вычисляем внешний хэш с серверным ключом
        var outer = new byte[innerHash.Length + serverKey.Length];
        Buffer.BlockCopy(innerHash, 0, outer, 0, innerHash.Length);
        Buffer.BlockCopy(serverKey, 0, outer, innerHash.Length, serverKey.Length);

        return md5.ComputeHash(outer);
    }

    /// <summary>
    /// Конвертирует MD5-хэш в hex-строку (без разделителей, нижний регистр).
    /// Например: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".
    /// </summary>
    /// <param name="hash">MD5-хэш (16 байт).</param>
    /// <returns>Hex-строка из 32 символов.</returns>
    public static string HashToHex(byte[] hash)
    {
        return BitConverter.ToString(hash).Replace("-", "").ToLower();
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

const int PBKDF2_ITERATIONS = 50000;
const int KEY_SIZE_BYTES = 32;
const string S2FAENCRYPTKEY_ENVVAR = "S2FAENCRYPTKEY";

/// <summary>
/// Generates an encryption key derived using a password, a random salt, and specified number of rounds of PBKDF2
/// 
/// TODO: pass in password via SecureString?
/// </summary>
/// <param name="password"></param>
/// <param name="salt"></param>
/// <returns></returns>
byte[] GetEncryptionKey(string password, string salt)
{
    if (string.IsNullOrEmpty(password))
    {
        throw new ArgumentException("Password is empty");
    }
    if (string.IsNullOrEmpty(salt))
    {
        throw new ArgumentException("Salt is empty");
    }
    using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(Encoding.ASCII.GetBytes(password), Convert.FromBase64String(salt), PBKDF2_ITERATIONS))
    {
        return pbkdf2.GetBytes(KEY_SIZE_BYTES);
    }
}

/// <summary>
/// Tries to decrypt and return data given an encrypted base64 encoded string. Must use the same
/// password, salt, IV, and ciphertext that was used during the original encryption of the data.
/// </summary>
/// <param name="password"></param>
/// <param name="passwordSalt"></param>
/// <param name="IV">Initialization Vector</param>
/// <param name="encryptedData"></param>
/// <returns></returns>
string DecryptData(string password, string passwordSalt, string IV, string encryptedData)
{
    if (string.IsNullOrEmpty(password))
    {
        throw new ArgumentException("Password is empty");
    }
    if (string.IsNullOrEmpty(passwordSalt))
    {
        throw new ArgumentException("Salt is empty");
    }
    if (string.IsNullOrEmpty(IV))
    {
        throw new ArgumentException("Initialization Vector is empty");
    }
    if (string.IsNullOrEmpty(encryptedData))
    {
        throw new ArgumentException("Encrypted data is empty");
    }

    byte[] cipherText = Convert.FromBase64String(encryptedData);
    byte[] key = GetEncryptionKey(password, passwordSalt);
    string plaintext = null;

    using (RijndaelManaged aes256 = new RijndaelManaged())
    {
        aes256.IV = Convert.FromBase64String(IV);
        aes256.Key = key;
        aes256.Padding = PaddingMode.PKCS7;
        aes256.Mode = CipherMode.CBC;

        //create decryptor to perform the stream transform
        ICryptoTransform decryptor = aes256.CreateDecryptor(aes256.Key, aes256.IV);

        //wrap in a try since a bad password yields a bad key, which would throw an exception on decrypt
        try
        {
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }
        catch (CryptographicException)
        {
            plaintext = null;
        }
    }
    return plaintext;
}

string[] arguments = Environment.GetCommandLineArgs();
string? encryptionPassword = Environment.GetEnvironmentVariable(S2FAENCRYPTKEY_ENVVAR);

string? manifestPath = null;
try
{
    manifestPath = System.IO.Path.GetFullPath((string?)arguments.GetValue(1)!);
}
catch
{
    Console.WriteLine("Manifest path not passed as argument");
    Environment.Exit(1);
}

SharedSecret.Manifest? manifest = null;
try
{
    using FileStream openStream = File.OpenRead(manifestPath);
    manifest = await JsonSerializer.DeserializeAsync<SharedSecret.Manifest>(openStream);
}
catch (FileNotFoundException ex)
{
    Console.WriteLine(ex.Message);
    Environment.Exit(1);
}

if (encryptionPassword == null)
{
    Console.WriteLine("Encryption password must exist in ENV:S2FAENCRYPTKEY");
    Environment.Exit(1);
}

var valuesToPrint = new List<JsonObject>();
foreach (var kv in manifest!.Entries)
{
    var maFilePath = System.IO.Path.GetFullPath(kv.Filename);
    var maFile = await File.ReadAllTextAsync(maFilePath);

    string decryptedText = DecryptData(
        encryptionPassword,
        kv.Salt,
        kv.IV,
        maFile
    );

    var value = JsonValue.Parse(decryptedText);
    var result = value as JsonObject;

    var format = $"{{ \"steam_id\":\"{kv.SteamID}\", \"shared_secret\":\"{(string)result!["shared_secret"]!}\" }}";
    var print = JsonValue.Parse(format);
    valuesToPrint.Add(print as JsonObject);
}

Console.WriteLine(JsonValue.Create(valuesToPrint).ToString());

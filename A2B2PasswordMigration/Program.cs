using System.Security.Cryptography;
using System.Text;


// https://github.com/drupal/drupal/blob/7.x/includes/password.inc - what this was rewritten from.

//Hash and salt the password
string password_crypt(string algo, string password, string setting)
{
    if(password.Length > 512)
    {
        return "";
    }

    setting = setting.Substring(0, 12);

    if (setting[0] != '$' || setting[2] != '$')
    {
        return "";
    }

    int countLog2 = getlogcount(setting);
    int count = 1 << countLog2;

    string salt = setting.Substring(4,8);

    var provider = SHA512.Create();
    byte[] bytes = provider.ComputeHash(Encoding.ASCII.GetBytes(salt + password));
    for (int i = 0; i < count; i++)
    {
        byte[] passEncode = Encoding.ASCII.GetBytes(password);
        byte[] newbytes = new byte[bytes.Length + Encoding.ASCII.GetBytes(password).Length];
        Buffer.BlockCopy(bytes, 0, newbytes, 0, bytes.Length);
        Buffer.BlockCopy(passEncode, 0, newbytes, bytes.Length, passEncode.Length);
        bytes = provider.ComputeHash(newbytes);
    }

    string b64 = tobase64(bytes, bytes.Length);
    string theHash = setting + b64;
    string finalHash = theHash.Substring(0, 55);


    return finalHash;
    
}


// This function makes absolutley no sense. Why they wouldn't just use PHP's built-in Base64 encoder is beyond me.
// Convert the hash bytearray to Base64.
string tobase64(byte[] input, int count)
{
    string output = "";
    int i = 0;
    string itoa64 = _password_itoa64();
    do
    {
        //string value = ord($input[$i++]);
        var value = (int)input[i++];
        //$output.= $itoa64[$value & 0x3f];
        output += itoa64[value & 0x3f];
        //if ($i < $count) {
        if (i < count)
        {
            //$value |= ord($input[$i]) << 8;
            //value = ((byte)(value | input[i] << 8));
            value |= input[i] << 8;
        }
        //$output.= $itoa64[($value >> 6) & 0x3f];
        output += itoa64[(value >> 6) & 0x3f];
        //if ($i++ >= $count) {
        if (i++ >= count)
        {
            break;
        }
        //if ($i < $count) {
        if (i < count)
        {
            //$value |= ord($input[$i]) << 16;
            //value = (byte)(value | input[i] << 16);
            value |= input[i] << 16;
        }
        //$output.= $itoa64[($value >> 12) & 0x3f];
        output += itoa64[(value >> 12) & 0x3f];
        //if ($i++ >= $count) {
        if (i++ >= count)
        {
            break;
        }
        //$output.= $itoa64[($value >> 18) & 0x3f];
        output += itoa64[(value >> 18) & 0x3f];
    } while (i < count);

    return output;




}


// Why???
string _password_itoa64()
{
    return "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
}

// shrug
int getlogcount(string setting)
{
    string itoa64 = _password_itoa64();
    return itoa64.IndexOf(setting[3]);
}

//Call this function. It will return true if the password matches the hash.
bool checkpass(string password, string hashed)
{

    string hash = password_crypt("sha512", password, hashed);
    return hash == hashed;
}
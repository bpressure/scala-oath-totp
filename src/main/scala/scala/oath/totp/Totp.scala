package scala.oath.totp

import org.apache.commons.codec.binary.Base32

case class Totp(service: String, secret: Array[Byte], digits: Int = 6, algorithm: MAC = SHA256, steps: Long = 30, issuer: Option[String] = None) {
    require(digits == 6 || digits == 8, "digits has to be 6 or 8")

    private[this] def toBase32(array: Array[Byte]): String = new Base32().encodeToString(array)
    private[this] def hashTimestamp(timestamp: Long) = algorithm.mac(secret, longToBytes(timestamp))
    private[this] def longToBytes(input: Long): Array[Byte] = {
        val array = Array.ofDim[Byte](8); var pos = 7; var long = input
        while (pos >= 0) { array(pos) = (long & 0xff).toByte; long >>= 8; pos -= 1 }
        array 
    }
    private[this] def bytesToInt(Array: Array[Byte], offset: Int): Int = {
        var result = 0; var pos = offset
        while (pos < offset + 4) { result <<= 8; result |= 0xFF & Array(pos); pos += 1 }
        result;
    }
    def generate(): String = generate(System.currentTimeMillis)
    def generate(time: Long): String = {
        val hash = hashTimestamp(time / 1000L / steps)
        val offset = hash(hash.length - 1) & 0xf;
        var otp = bytesToInt(hash, offset) & 0x7FFFFFFF;

        val chars = Array.ofDim[Char](digits)
        var d = digits
        while (d > 0) {
            d -= 1
            chars(d) = ('0' + (otp % 10)).toChar
            otp /= 10
        }
        new String(chars)
    }

    def uri = s"otpauth://totp/${service}?secret=${toBase32(secret)}&digits=$digits&algorithm=${algorithm.name}" +
        issuer.map("&issuer=" + _).getOrElse("")
} 
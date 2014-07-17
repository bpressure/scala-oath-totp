package scala.oath.totp

import javax.crypto._
import javax.crypto.spec._

sealed class MAC(val name: String, alg: String) {
    def mac(key: Array[Byte], data: Array[Byte]) = {
        val mac = Mac.getInstance(alg)
        val spec = new SecretKeySpec(key, "RAW")
        mac.init(spec)
        mac.doFinal(data)
    }
} 
case object SHA1 extends MAC("SHA1", "HmacSHA1")
case object SHA256 extends MAC("SHA256", "HmacSHA256")
case object SHA512 extends MAC("SHA512", "HmacSHA512")
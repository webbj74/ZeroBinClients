<?php

/** Exceptions **/

/** @class Ciphertext is corrupt. */
class ZeroBinSJCLCorrupt extends Exception { 
  public function __construct($message, $code = 0, Exception $previous = null) {
    parent::__construct("CORRUPT: " . $message, $code, $previous);
  }
}

/** @class Invalid parameter. */
class ZeroBinSJCLInvalid extends Exception { 
  public function __construct($message, $code = 0, Exception $previous = null) {
    parent::__construct("INVALID: " . $message, $code, $previous);
  }
}

/** @class Bug or missing feature in SJCL. */
class ZeroBinSJCLBug extends Exception { 
  public function __construct($message, $code = 0, Exception $previous = null) {
    parent::__construct("BUG: " . $message, $code, $previous);
  }
}


class ZeroBinSJCLCodecBase64 {
  public static $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  // equiv of js binary operator a>>>b 
  public static function zeroFill($a,$b) {
    return ($a >= 0) 
      ? bindec(decbin($a>>$b)) //simply right shift for positive number
      : bindec(substr(decbin($a>>$b), $b)) // zero fill on the left side
      ;
  }

  // equiv of js binary operator x<<n
  public static function shiftl32($x, $n)
  {
    if ($n < 32) {
    	$b = decbin($x);
    	$b = str_pad($b, 32, '0', STR_PAD_LEFT);
    	$b = $b . str_repeat('0', $n);
    	$b = substr($b, strlen($b) - 32);
      return ($b[0] == '1')
        ? (-(pow(2, 31) - bindec(substr($b, 1))))
        : bindec($b)
        ;
    }
    else {
      return 0;
    }
  }

     /** Convert from a base64 string to a bitArray */
  public static function toBits($str) {
    $str = preg_replace('/\s|=/', '', $str);
    $out = array();
    $bits = 0;
    $c = self::$chars;
    $ta = 0;

    for ($i=0; $i < strlen($str); $i++) {
      $x = strpos($c,$str[$i]);
      if ($x < 0) {
        throw new ZeroBinSJCLBugInvalid("this isn't base64!");
      }
      if ($bits > 26) {
        $bits -= 26;
        array_push($out, ($ta ^ self::zeroFill($x,$bits)));
        $ta  = self::shiftl32($x, (32-$bits));
      }
      else {
        $bits += 6;
        $ta ^= self::shiftl32($x, (32-$bits));
      }
    }
    if ($bits&56) {
      array_push($out, (sjcl.bitArray.partial($bits&56, $ta, 1)));
    }
    return $out;
  }
}

/** @class SJCL-compatible encryption for ZeroBin */
class ZeroBinSJCL {

  /** Default values for encryption */
  public static $defaults = array (
    'v' => 1,
    'iter' => 1000,
    'ks' => 128,
    'ts' =>64,
    'mode' => 'ccm',
    'adata' => '',
    'cipher' => 'aes',
  );
  
  /** Return a string of random
  public static function randomBase64Str($length = 44) {
    $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    $randomString = '';
    for ($i = 1; $i < $length; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }
    return ($randomString . '=');
  }

  /** Simple encryption function.
   * @param {String|bitArray} password The password or key.
   * @param {String} plaintext The data to encrypt.
   * @param {Object} [params] The parameters including tag, iv and salt.
   * @param {Object} [rp] A returned version with filled-in parameters.
   * @return {String} The ciphertext.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   */
  public static function encrypt ($password, $plaintext, $params = array(), $rp = array()) {
    $p = array_merge(array_merge(array('iv' => randomBase64Str()), self::$defaults), $params);
  
    if (is_string($p['salt'])) {
      $p['salt_str'] = $p['salt'];
      $p['salt'] = ZeroBinSJCLCodecBase64::toBits($p['salt']);
    }
    if (is_string($p['iv'])) {
      $p['iv_str'] = $p['iv'];
      $p['iv'] = ZeroBinSJCLCodecBase64::toBits($p['iv']);
    }
/***
      
      if (!sjcl.mode[p.mode] ||
          !sjcl.cipher[p.cipher] ||
          (typeof password === "string" && p.iter <= 100) ||
          (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
          (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
          (p.iv.length < 2 || p.iv.length > 4)) {
        throw new sjcl.exception.invalid("json encrypt: invalid parameters");
      }
      
      if (typeof password === "string") {
        tmp = sjcl.misc.cachedPbkdf2(password, p);
        password = tmp.key.slice(0,p.ks/32);
        p.salt = tmp.salt;
      }
      if (typeof plaintext === "string") {
        plaintext = sjcl.codec.utf8String.toBits(plaintext);
      }
      prp = new sjcl.cipher[p.cipher](password);
      
      // return the json data
      j._add(rp, p);
      rp.key = password;
      
      // do the encryption
      p.ct = sjcl.mode[p.mode].encrypt(prp, plaintext, p.iv, p.adata, p.tag);
      
      return j.encode(j._subtract(p, j.defaults));
***/
    throw new ZeroBinSJCLBug("ZeroBinSJCL::encrypt() has not been fully implemented.");
  }

  /**
   *  Simple decryption function.
   *
   * @param {String|bitArray} password The password or key.
   * @param {String} ciphertext The ciphertext to decrypt.
   * @param {Object} [params] Additional non-default parameters.
   * @param {Object} [rp] A returned object with filled parameters.
   *
   * @return {String} The plaintext.
   *
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
   */
  public static function decrypt($password, $ciphertext, $params = array(), $rp = array()) {
    $p = array_merge(array_merge(self::$defaults, (array)json_decode($ciphertext)), $params);
    if (is_string($p['salt'])) {
      $p['salt_str'] = $p['salt'];
      $p['salt'] = ZeroBinSJCLCodecBase64::toBits($p['salt']);
    }
    if (is_string($p['iv'])) {
      $p['iv_str'] = $p['iv'];
      $p['iv'] = ZeroBinSJCLCodecBase64::toBits($p['iv']);
    }
/***
      if (!sjcl.mode[p.mode] ||
          !sjcl.cipher[p.cipher] ||
          (typeof password === "string" && p.iter <= 100) ||
          (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
          (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
          (!p.iv) ||
          (p.iv.length < 2 || p.iv.length > 4)) {
        throw new sjcl.exception.invalid("json decrypt: invalid parameters");
      }
      
      if (typeof password === "string") {
        tmp = sjcl.misc.cachedPbkdf2(password, p);
        password = tmp.key.slice(0,p.ks/32);
        p.salt  = tmp.salt;
      }
      prp = new sjcl.cipher[p.cipher](password);
      
      // do the decryption
      ct = sjcl.mode[p.mode].decrypt(prp, p.ct, p.iv, p.adata, p.tag);
      
      // return the json data
      j._add(rp, p);
      rp.key = password;
      
      return sjcl.codec.utf8String.fromBits(ct);
      },
***/
    throw new \Exception("ZeroBinSJCL::decrypt() has not been fully implemented.");
  }
}

/**
  
  /** Encode a flat structure into a JSON string.
   * @param {Object} obj The structure to encode.
   * @return {String} A JSON string.
   * @throws {sjcl.exception.invalid} if obj has a non-alphanumeric property.
   * @throws {sjcl.exception.bug} if a parameter has an unsupported type.
   *
  encode: function (obj) {
    var i, out='{', comma='';
    for (i in obj) {
      if (obj.hasOwnProperty(i)) {
        if (!i.match(/^[a-z0-9]+$/i)) {
          throw new sjcl.exception.invalid("json encode: invalid property name");
        }
        out += comma + i + ':';
        comma = ',';
        
        switch (typeof obj[i]) {
        case 'number':
        case 'boolean':
          out += obj[i];
          break;
          
        case 'string':
          out += '"' + escape(obj[i]) + '"';
          break;
        
        case 'object':
          out += '"' + sjcl.codec.base64.fromBits(obj[i],1) + '"';
          break;
        
        default:
          throw new sjcl.exception.bug("json encode: unsupported type");
        }
      }
    }
    return out+'}';
  },
  
  /** Decode a simple (flat) JSON string into a structure.  The ciphertext,
   * adata, salt and iv will be base64-decoded.
   * @param {String} str The string.
   * @return {Object} The decoded structure.
   * @throws {sjcl.exception.invalid} if str isn't (simple) JSON.
   *
  decode: function (str) {
    str = str.replace(/\s/g,'');
    if (!str.match(/^\{.*\}$/)) { 
      throw new sjcl.exception.invalid("json decode: this isn't json!");
    }
    var a = str.replace(/^\{|\}$/g, '').split(/,/), out={}, i, m;
    for (i=0; i<a.length; i++) {
      if (!(m=a[i].match(/^([a-z][a-z0-9]*):(?:(\d+)|"([a-z0-9+\/%*_.@=\-]*)")$/i))) {
        throw new sjcl.exception.invalid("json decode: this isn't json!");
      }
      if (m[2]) {
        out[m[1]] = parseInt(m[2],10);
      } else {
        out[m[1]] = m[1].match(/^(ct|salt|iv)$/) ? sjcl.codec.base64.toBits(m[3]) : unescape(m[3]);
      }
    }
    return out;
  },
  
  /** Insert all elements of src into target, modifying and returning target.
   * @param {Object} target The object to be modified.
   * @param {Object} src The object to pull data from.
   * @param {boolean} [requireSame=false] If true, throw an exception if any field of target differs from corresponding field of src.
   * @return {Object} target.
   * @private
   *
  _add: function (target, src, requireSame) {
    if (target === undefined) { target = {}; }
    if (src === undefined) { return target; }
    var i;
    for (i in src) {
      if (src.hasOwnProperty(i)) {
        if (requireSame && target[i] !== undefined && target[i] !== src[i]) {
          throw new sjcl.exception.invalid("required parameter overridden");
        }
        target[i] = src[i];
      }
    }
    return target;
  },
  
  /** Remove all elements of minus from plus.  Does not modify plus.
   * @private
   *
  _subtract: function (plus, minus) {
    var out = {}, i;
    
    for (i in plus) {
      if (plus.hasOwnProperty(i) && plus[i] !== minus[i]) {
        out[i] = plus[i];
      }
    }
    
    return out;
  },
  
  /** Return only the specified elements of src.
   * @private
   *
  _filter: function (src, filter) {
    var out = {}, i;
    for (i=0; i<filter.length; i++) {
      if (src[filter[i]] !== undefined) {
        out[filter[i]] = src[filter[i]];
      }
    }
    return out;
  }
};

/** Simple encryption function; convenient shorthand for sjcl.json.encrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} plaintext The data to encrypt.
 * @param {Object} [params] The parameters including tag, iv and salt.
 * @param {Object} [rp] A returned version with filled-in parameters.
 * @return {String} The ciphertext.
 *
sjcl.encrypt = sjcl.json.encrypt;

/** Simple decryption function; convenient shorthand for sjcl.json.decrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} ciphertext The ciphertext to decrypt.
 * @param {Object} [params] Additional non-default parameters.
 * @param {Object} [rp] A returned object with filled parameters.
 * @return {String} The plaintext.
 *
sjcl.decrypt = sjcl.json.decrypt;

/** The cache for cachedPbkdf2.
 * @private
 *
sjcl.misc._pbkdf2Cache = {};

/** Cached PBKDF2 key derivation.
 * @param {String} The password.  
 * @param {Object} The derivation params (iteration count and optional salt).
 * @return {Object} The derived data in key, the salt in salt.
 *
sjcl.misc.cachedPbkdf2 = function (password, obj) {
  var cache = sjcl.misc._pbkdf2Cache, c, cp, str, salt, iter;
  
  obj = obj || {};
  iter = obj.iter || 1000;
  
  // open the cache for this password and iteration count
  cp = cache[password] = cache[password] || {};
  c = cp[iter] = cp[iter] || { firstSalt: (obj.salt && obj.salt.length) ?
                     obj.salt.slice(0) : sjcl.random.randomWords(2,0) };
          
  salt = (obj.salt === undefined) ? c.firstSalt : obj.salt;
  
  c[salt] = c[salt] || sjcl.misc.pbkdf2(password, salt, obj.iter);
  return { key: c[salt].slice(0), salt:salt.slice(0) };
};



**/

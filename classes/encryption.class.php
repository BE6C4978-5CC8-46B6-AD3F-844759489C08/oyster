<?php
	// Fallbacks incase the configuration file is missing.
	if (!defined('ENCRYPT_KEY'))
		define('ENCRYPT_KEY', 'XwNwQc3ittor1nishO0KRL81A7VM5e20');

	/**
	* @brief Encrypts, decrypts, and generates secure tokens.
	* @todo N/A
	* @date 2014
	*/
	class Encryption
	{
		/**
		* @brief Generates a secure, random token.
		*
		* @param int $Length
		*  How long the generated token should be.
		*
		* @return string
		*  The token generated.
		*/
		public static function generate_token($Length = 256)
		{
			$Token = '';
			$Alphabet = '-_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

			for ($Index = 0; $Index < $Length; ++$Index)
			{
				do {
					$Rand = hexdec(bin2hex(openssl_random_pseudo_bytes(1))) & 127;
				} while ($Rand >= 64);

				$Token .= $Alphabet[$Rand];
			}

			return $Token;
		}

		/**
		* @brief Encodes data into hexadecimal format.
		*
		* @param string $Data
		*  The data to encode.
		*
		* @return string
		*  The encoded data.
		*/
		public static function hex_encode($Data)
		{
			$HexData = '';

			for ($Index = 0; $Index < strlen($Data); ++$Index) {
				$HexData .= str_pad(dechex(ord($Data[$Index])), 3, '0', STR_PAD_LEFT);
			}

			return $HexData;
		}

		/**
		* @brief Decodes data from hexadecimal format.
		*
		* @param string $HexData
		*  The data to decode.
		*
		* @return string
		*  The decoded data.
		*/
		public static function hex_decode($HexData)
		{
			$Data = '';

			for ($Index = 0; $Index <= strlen($HexData); $Index += 3) {
				$Data .= chr(hexdec(substr($HexData, $Index, 3)));
			}

			return $Data;
		}

		/**
		* @brief Encrypts data with AES compliant MCRYPT_RIJNDAEL_128.
		*
		* @param string $Data
		*  The data to encrypt.
		* @param string $Key
		*  The key to encrypt with.
		*
		* @return string
		*  A base64 encoded version of the initialization vector and encrypted data.
		*/
		public static function encrypt($Data, $Key = ENCRYPT_KEY)
		{
			srand();
			$Data = str_pad($Data, 32 - strlen($Data));
			$IV = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC), MCRYPT_RAND);
			$Encrypted_Data = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $Key, $Data, MCRYPT_MODE_CBC, $IV);
			return base64_encode($IV . $Encrypted_Data);
		}

		/**
		* @brief Decrypts data with AES compliant MCRYPT_RIJNDAEL_128.
		*
		* @param string $Data
		*  The data to decrypt.
		* @param string $Key
		*  The key to decrypt with.
		*
		* @return string
		*  The decrypted data.
		*/
		public static function decrypt($Data, $Key = ENCRYPT_KEY)
		{
			if (empty($Data))
				return '';

			$IV = substr(base64_decode($Data), 0, 16);
			$Data = substr(base64_decode($Data), 16);
			return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $Key, $Data, MCRYPT_MODE_CBC, $IV));
		}
	}
?>
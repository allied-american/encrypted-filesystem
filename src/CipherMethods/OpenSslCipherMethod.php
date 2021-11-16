<?php

namespace SmaatCoda\EncryptedFilesystem\CipherMethods;

use InvalidArgumentException;
use LogicException;
use SmaatCoda\EncryptedFilesystem\Interfaces\CipherMethodInterface;
use SmaatCoda\EncryptedFilesystem\Interfaces\RequiresIvContract;
use SmaatCoda\EncryptedFilesystem\Interfaces\RequiresPaddingContract;

class OpenSslCipherMethod implements CipherMethodInterface, RequiresIvContract, RequiresPaddingContract
{
    const AES_128_CBC = 'aes-128-cbc';
    const AES_128_CFB = 'aes-128-cfb';
    const AES_128_CFB1 = 'aes-128-cfb1';
    const AES_128_CFB8 = 'aes-128-cfb8';
    const AES_128_OFB = 'aes-128-ofb';
    const AES_192_CBC = 'aes-192-cbc';
    const AES_192_CFB = 'aes-192-cfb';
    const AES_192_CFB1 = 'aes-192-cfb1';
    const AES_192_CFB8 = 'aes-192-cfb8';
    const AES_192_OFB = 'aes-192-ofb';
    const AES_256_CBC = 'aes-256-cbc';
    const AES_256_CFB = 'aes-256-cfb';
    const AES_256_CFB1 = 'aes-256-cfb1';
    const AES_256_CFB8 = 'aes-256-cfb8';
    const AES_256_OFB = 'aes-256-ofb';
    const BF_CBC = 'bf-cbc';
    const BF_CFB = 'bf-cfb';
    const BF_OFB = 'bf-ofb';
    const CAST5_CBC = 'cast5-cbc';
    const CAST5_CFB = 'cast5-cfb';
    const CAST5_OFB = 'cast5-ofb';
    const IDEA_CBC = 'idea-cbc';
    const IDEA_CFB = 'idea-cfb';
    const IDEA_OFB = 'idea-ofb';

    /**
     * @var
     */
    protected $iv;

    /**
     * @var
     */
    protected $key;

    /**
     * @var mixed|string
     */
    protected $algorithm;

    /**
     * @var false|int
     */
    protected $blockSize;

    /**
     * OpenSslCipherMethod constructor.
     * @param $key
     * @param $algorithm
     */
    public function __construct($key, $algorithm = self::AES_256_CBC)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;

        $this->blockSize = openssl_cipher_iv_length($this->algorithm);
    }

    /**
     * @param string $iv
     */
    public function setIv(string $iv)
    {
        $this->iv = $iv;

        if (strlen($iv) !== $this->blockSize) {
            throw new InvalidArgumentException("Invalid initialization vector $iv");
        }
    }

    /**
     * @return string
     */
    public function getIv(): string
    {
        return $this->iv;
    }

    /**
     * @param string $key
     */
    public function setKey(string $key): void
    {
        $this->key = $key;
    }

    /**
     * @param string $algorithm
     */
    public function setAlgorithm(string $algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    /**
     * @return false|int
     */
    public function getBlockSize(): int
    {
        return $this->blockSize;
    }

    /**
     * @param int $filesize
     * @return int
     */
    public function getPaddingSize(int $filesize): int
    {
        return $this->blockSize - $filesize % $this->blockSize;
    }

    /**
     * @return int
     */
    public function getIvSize(): int
    {
        return $this->blockSize;
    }

    /**
     * @param string $plaintext
     * @param bool $eof
     * @return string
     */
    public function encrypt(string $plaintext, bool $eof = false): string
    {
        $prefix = '';

        if (empty($this->iv)) {
            $this->generateIv();

            $prefix = $this->iv;
        }

        // Use no padding except at the end of file
        $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;

        if ($eof) {
            $options = OPENSSL_RAW_DATA;
        }

        $ciphertext = openssl_encrypt(
            $plaintext,
            $this->algorithm,
            $this->key,
            $options,
            $this->iv
        );

        $this->setIv(substr($ciphertext, 0, $this->blockSize));

        return $prefix . $ciphertext;
    }

    /**
     * @param string $ciphertext
     * @param bool $eof
     * @return string
     */
    public function decrypt(string $ciphertext, bool $eof = false): string
    {
        if (empty($this->iv)) {
            $this->setIv(substr($ciphertext, 0, $this->blockSize));
            $ciphertext = substr($ciphertext, $this->blockSize);

            if (empty($ciphertext)) {
                return '';
            }
        }

        // Use no padding except at the end of file
        $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;

        if ($eof) {
            $options = OPENSSL_RAW_DATA;
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            $this->algorithm,
            $this->key,
            $options,
            $this->iv
        );

        $this->setIv(substr($ciphertext, 0, $this->blockSize));

        return $plaintext;
    }

    /**
     * @return string
     */
    public function generateIv(): string
    {
        return $this->iv = openssl_random_pseudo_bytes($this->blockSize);
    }

    /**
     *
     */
    public function reset(): void
    {
        $this->iv = null;
    }

    /**
     * @param int $offset
     * @param int|string $whence
     */
    public function seek(int $offset, string $whence = SEEK_SET)
    {
        if ($offset === 0 && (int)$whence === SEEK_SET) {
            $this->iv = null;
        } else {
            throw new LogicException('Only rewinding is supported');
        }
    }
}

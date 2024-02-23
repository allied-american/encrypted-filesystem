<?php

namespace SmaatCoda\EncryptedFilesystem\FilesystemAdapters;

use GuzzleHttp\Psr7\Stream;
use League\Flysystem\Adapter\Local;
use League\Flysystem\Config;
use SmaatCoda\EncryptedFilesystem\EncryptionStreams\DecryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\EncryptionStreams\EncryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\Interfaces\CipherMethodInterface;

class EncryptedLocalAdapter extends Local
{
    /**
     * This extension is appended to encrypted files and will be checked for before decryption
     */
    const FILENAME_POSTFIX = '.enc';

    /**
     * @var CipherMethodInterface
     */
    protected $cipherMethod;

    /**
     * EncryptedFilesystemAdapter constructor.
     * @param CipherMethodInterface $cipherMethod
     * @param $root
     * @param int $writeFlags
     * @param int $linkHandling
     * @param array $permissions
     */
    public function __construct(CipherMethodInterface $cipherMethod, $root, $writeFlags = LOCK_EX, $linkHandling = self::DISALLOW_LINKS, array $permissions = [])
    {
        $this->cipherMethod = $cipherMethod;

        parent::__construct($root, $writeFlags, $linkHandling, $permissions);
    }

    /** @inheritdoc */
    public function has($path)
    {
        return parent::has($this->attachEncryptionMarkers($path));
    }

    /** @inheritdoc */
    public function write($path, $contents, Config $config)
    {
        $location = $this->attachEncryptionMarkers($this->applyPathPrefix($path));
        $this->ensureDirectory(dirname($location));

        // This driver works exclusively with streams, so transform the contents into a stream
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $contents);
        rewind($stream);

        $result = $this->writeStream($path, $stream, $config);
        $result['contents'] = $contents;

        if ($visibility = $config->get('visibility')) {
            $result['visibility'] = $visibility;
            $this->setVisibility($path, $visibility);
        }

        return $result;
    }

    /** @inheritdoc */
    public function writeStream($path, $resource, Config $config)
    {
        $location = $this->attachEncryptionMarkers($this->applyPathPrefix($path));
        $this->ensureDirectory(dirname($location));
        $this->cipherMethod->reset();

        $stream = new Stream($resource);
        $encryptedStream = new EncryptingStreamDecorator($stream, $this->cipherMethod);
        $outputStream = new Stream(fopen($location, 'wb'));

        while (!$encryptedStream->eof()) {
            $outputStream->write($encryptedStream->read($this->cipherMethod->getBlockSize()));
        }

        $type = 'file';
        $size = $encryptedStream->getSize();

        $result = compact('type', 'path', 'size');

        if ($visibility = $config->get('visibility')) {
            $this->setVisibility($path, $visibility);
            $result['visibility'] = $visibility;
        }

        return $result;
    }

    /** @inheritdoc */
    public function readStream($path)
    {
        $location = $this->attachEncryptionMarkers($this->applyPathPrefix($path));
        $this->cipherMethod->reset();

        $stream = new Stream(fopen($location, 'rb'));
        $decryptedStream = new DecryptingStreamDecorator($stream, $this->cipherMethod);

        return ['type' => 'file', 'path' => $path, 'stream' => $decryptedStream];
    }

    /** @inheritdoc */
    public function update($path, $contents, Config $config)
    {
        return $this->write($path, $contents, $config);
    }

    /** @inheritdoc */
    public function read($path)
    {
        $location = $this->attachEncryptionMarkers($this->applyPathPrefix($path));
        $this->cipherMethod->reset();

        $stream = new Stream(fopen($location, 'rb'));
        $decryptedStream = new DecryptingStreamDecorator($stream, $this->cipherMethod);

        $contents = '';
        while (!$decryptedStream->eof()) {
            $contents .= $decryptedStream->read($this->cipherMethod->getBlockSize());
        }

        if ($contents === false) {
            return false;
        }

        return ['type' => 'file', 'path' => $path, 'contents' => $contents];
    }

    /** @inheritdoc */
    public function rename($path, $newpath)
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
            $newpath = $this->attachEncryptionMarkers($newpath);
        }

        return parent::rename($path, $newpath);
    }

    /** @inheritdoc */
    public function copy($path, $newpath)
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
            $newpath = $this->attachEncryptionMarkers($newpath);
        }

        return parent::copy($path, $newpath);
    }

    /** @inheritdoc */
    public function delete($path)
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
        }

        return parent::delete($path);
    }

    /** @inheritdoc */
    public function getMetadata($path)
    {
        $path = $this->attachEncryptionMarkers($path);

        return parent::getMetadata($path);
    }

    /** @inheritdoc */
    public function getSize($path)
    {
        return parent::getSize($path);
    }

    /** @inheritdoc */
    public function getMimetype($path)
    {
        $path = $this->attachEncryptionMarkers($path);

        return parent::getMimetype($path);
    }

    /** @inheritdoc */
    public function getTimestamp($path)
    {
        $path = $this->attachEncryptionMarkers($path);

        return parent::getTimestamp($path);
    }

    /** @inheritdoc */
    public function getVisibility($path)
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
        }

        return parent::getVisibility($path);
    }

    /** @inheritdoc */
    public function setVisibility($path, $visibility)
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
        }

        return parent::setVisibility($path, $visibility);
    }

    /**
     * @param $destPath
     * @return string
     */
    protected function attachEncryptionMarkers($destPath)
    {
        if (!str_ends_with($destPath, self::FILENAME_POSTFIX)) {
            return $destPath . self::FILENAME_POSTFIX;
        }
        return $destPath;
    }

    /**
     * @param $sourceRealPath
     * @return string|string[]|null
     */
    protected function detachEncryptionMarkers($sourceRealPath)
    {
        return preg_replace('/(' . self::FILENAME_POSTFIX . ')$/', '', $sourceRealPath);
    }
}

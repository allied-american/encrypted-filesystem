<?php

namespace SmaatCoda\EncryptedFilesystem\FilesystemAdapters;

use GuzzleHttp\Psr7\Stream;
use League\Flysystem\FileAttributes;
use League\Flysystem\Local\LocalFilesystemAdapter;
use League\Flysystem\Config;
use League\Flysystem\PathPrefixer;
use League\Flysystem\UnixVisibility\PortableVisibilityConverter;
use League\Flysystem\UnixVisibility\VisibilityConverter;
use SmaatCoda\EncryptedFilesystem\EncryptionStreams\DecryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\EncryptionStreams\EncryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\Interfaces\CipherMethodInterface;

class EncryptedLocalAdapter extends LocalFilesystemAdapter
{
    /**
     * This extension is appended to encrypted files and will be checked for before decryption
     */
    const FILENAME_POSTFIX = '.enc';

    /**
     * @var PathPrefixer
     */
    private $prefixer;

    /**
     * @var VisibilityConverter
     */
    private $visibility;

    /**
     * @var string
     */
    private $rootLocation;

    /**
     * @var bool
     */
    private $rootLocationIsSetup = false;

    /**
     * @var CipherMethodInterface
     */
    protected $cipherMethod;

    /**
     * EncryptedFilesystemAdapter constructor.
     * @param  CipherMethodInterface  $cipherMethod
     * @param  string  $location
     * @param  int  $writeFlags
     * @param  int  $linkHandling
     */
    public function __construct(
        CipherMethodInterface $cipherMethod,
        string $location,
        int $writeFlags = LOCK_EX,
        int $linkHandling = self::DISALLOW_LINKS
    ) {
        $this->cipherMethod = $cipherMethod;
        $this->prefixer = new PathPrefixer($location, DIRECTORY_SEPARATOR);
        $this->visibility = new PortableVisibilityConverter();
        $this->rootLocation = $location;
        $this->ensureRootDirectoryExists();

        parent::__construct($location, $this->visibility, $writeFlags, $linkHandling);
    }

    /** @inheritdoc */
    public function fileExists(string $location): bool
    {
        return parent::fileExists($this->attachEncryptionMarkers($location));
    }

    /**
     * For compatibility with Illuminate\Filesystem\FilesystemAdapter::exists.
     */
    public function has($path): bool
    {
        return $this->fileExists($this->attachEncryptionMarkers($path)) || $this->directoryExists($path);
    }

    /** @inheritdoc */
    public function write(string $path, string $contents, Config $config): void
    {
        // This driver works exclusively with streams, so transform the contents into a stream.
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $contents);
        rewind($stream);

        $this->writeStream($path, $stream, $config);
    }

    /** @inheritdoc */
    public function writeStream(string $path, $contents, Config $config): void
    {
        $location = $this->attachEncryptionMarkers($path);
        $prefixedLocation = $this->prefixer->prefixPath($location);
        $this->ensureRootDirectoryExists();
        $this->ensureDirectoryExists(
            dirname($prefixedLocation),
            $this->resolveDirectoryVisibility($config->get(Config::OPTION_DIRECTORY_VISIBILITY))
        );
        error_clear_last();

        $this->cipherMethod->reset();

        $stream = new Stream($contents);
        $encryptedStream = new EncryptingStreamDecorator($stream, $this->cipherMethod);
        $outputStream = new Stream(fopen($prefixedLocation, 'wb'));

        while (!$encryptedStream->eof()) {
            $outputStream->write($encryptedStream->read($this->cipherMethod->getBlockSize()));
        }

        if ($visibility = $config->get(Config::OPTION_VISIBILITY)) {
            $this->setVisibility($path, (string) $visibility);
        }
    }

    /** @inheritdoc */
    public function read(string $path): string
    {
        // @todo Make sure the method is FS3 compatible.
        $location = $this->attachEncryptionMarkers($this->prefixer->prefixPath($path));
        $this->cipherMethod->reset();

        $stream = new Stream(fopen($location, 'rb'));
        $decryptedStream = new DecryptingStreamDecorator($stream, $this->cipherMethod);

        $contents = '';
        while (!$decryptedStream->eof()) {
            $contents .= $decryptedStream->read($this->cipherMethod->getBlockSize());
        }

        if ($contents === false) {
            return '';
        }

        return $contents;
    }

    /** @inheritdoc */
    public function readStream($path)
    {
        // @todo Make sure the method is FS3 compatible.
        $location = $this->attachEncryptionMarkers($this->prefixer->prefixPath($path));
        $this->cipherMethod->reset();

        $stream = new Stream(fopen($location, 'rb'));
        return new DecryptingStreamDecorator($stream, $this->cipherMethod);
    }

    /** @inheritdoc */
    public function move(string $source, string $destination, Config $config): void
    {
        if (!is_dir($source)) {
            $source = $this->attachEncryptionMarkers($source);
            $destination = $this->attachEncryptionMarkers($destination);
        }

        parent::move($source, $destination, $config);
    }

    /** @inheritdoc */
    public function copy(string $source, string $destination, Config $config): void
    {
        if (!is_dir($source)) {
            $source = $this->attachEncryptionMarkers($source);
            $destination = $this->attachEncryptionMarkers($destination);
        }

        parent::copy($source, $destination, $config);
    }

    /** @inheritdoc */
    public function delete(string $path): void
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
        }

        parent::delete($path);
    }

    /** @inheritdoc */
    public function fileSize(string $path): FileAttributes
    {
        // @todo Think how to handle it correctly.

        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
        }

        return parent::fileSize($path);
    }

    /** @inheritdoc */
    public function mimeType(string $path): FileAttributes
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
        }

        return parent::mimeType($path);
    }

    /** @inheritdoc */
    public function lastModified(string $path): FileAttributes
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
        }

        return parent::lastModified($path);
    }

    /** @inheritdoc */
    public function visibility(string $path): FileAttributes
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
        }

        return parent::visibility($path);
    }

    /** @inheritdoc */
    public function setVisibility(string $path, string $visibility): void
    {
        if (!is_dir($path)) {
            $path = $this->attachEncryptionMarkers($path);
        }

        parent::setVisibility($path, $visibility);
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

    private function ensureRootDirectoryExists(): void
    {
        if ($this->rootLocationIsSetup) {
            return;
        }

        $this->ensureDirectoryExists($this->rootLocation, $this->visibility->defaultForDirectories());
    }

    private function resolveDirectoryVisibility(?string $visibility): int
    {
        return $visibility === null ? $this->visibility->defaultForDirectories() : $this->visibility->forDirectory(
            $visibility
        );
    }

}

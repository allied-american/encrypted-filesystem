<?php


namespace SmaatCoda\EncryptedFilesystem\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;
use SmaatCoda\EncryptedFilesystem\Interfaces\CipherMethodInterface;
use SmaatCoda\EncryptedFilesystem\Interfaces\RequiresIvContract;
use SmaatCoda\EncryptedFilesystem\Interfaces\RequiresPaddingContract;

class EncryptingStreamDecorator implements StreamInterface
{
  use StreamDecoratorTrait;

  /**
   * @var StreamInterface
   */
  protected $stream;

  /**
   * @var CipherMethodInterface
   */
  protected $encryptor;

  /**
   * @var string
   */
  protected $buffer = '';

  /**
   * EncryptingStreamDecorator constructor.
   * @param StreamInterface $stream
   * @param CipherMethodInterface $encryptor
   */
  public function __construct(StreamInterface $stream, CipherMethodInterface $encryptor)
  {
    $this->stream = $stream;
    $this->encryptor = $encryptor;
  }

  /**
   * @param int $offset
   * @param int $whence
   */
  public function seek($offset, $whence = SEEK_SET): void
  {
    if ($whence === SEEK_CUR) {
      $offset = $this->tell() + $offset;
      $whence = SEEK_SET;
    }
    if ($whence === SEEK_SET) {
      $this->buffer = '';
      $wholeBlockOffset = $this->encryptor->getBlockSize() * ceil($offset / $this->encryptor->getBlockSize());
      $this->encryptor->seek($wholeBlockOffset, $whence);
      $this->stream->seek($wholeBlockOffset, $whence);
      $this->read($offset - $wholeBlockOffset);
    } else {
      throw new LogicException('Unrecognized whence.');
    }
  }

  /**
   * @param int $length
   * @return false|string
   */
  public function read($length): string
  {
    while (strlen($this->buffer) < $length && !$this->stream->eof()) {
      $plaintext = $this->stream->read(
//                $this->encryptor->getBlockSize() * ceil(($length - strlen($this->buffer)) / $this->encryptor->getBlockSize())
        $this->encryptor->getBlockSize()
      );

      $this->buffer .= $this->encryptor->encrypt($plaintext, $this->stream->eof());
    }

    $data = substr($this->buffer, 0, $length);
    $this->buffer = substr($this->buffer, $length);
    return $data;
  }

  /**
   * @return bool
   */
  public function eof(): bool
  {
    return $this->stream->eof() && empty($this->buffer);
  }

  /**
   * @return int|null
   */
  public function getSize(): ?int
  {
    $filesize = $this->stream->getSize();

    if ($this->encryptor instanceof RequiresPaddingContract) {
      $filesize += $this->encryptor->getPaddingSize($filesize);
    }

    if ($this->encryptor instanceof RequiresIvContract) {
      $filesize += $this->encryptor->getIvSize();
    }

    return $filesize;
  }

  /**
   * @return bool
   */
  public function isWritable(): bool
  {
    return false;
  }
}

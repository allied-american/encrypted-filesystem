<?php

namespace SmaatCoda\EncryptedFilesystem\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;
use SmaatCoda\EncryptedFilesystem\Interfaces\CipherMethodInterface;

class DecryptingStreamDecorator implements StreamInterface
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
    protected $plaintextBuffer = '';

    /**
     * @var string
     */
    protected $ciphertextBuffer = '';

    /**
     * DecryptingStreamDecorator constructor.
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
    public function seek($offset, $whence = SEEK_SET)
    {
        if ($whence === SEEK_CUR) {
            $offset = $this->tell() + $offset;
            $whence = SEEK_SET;
        }
        if ($whence === SEEK_SET) {
            $this->plaintextBuffer = '';

            $wholeBlockOffset = (int)($this->encryptor->getBlockSize() * ceil($offset / $this->encryptor->getBlockSize()));
            $this->encryptor->seek($wholeBlockOffset, $whence);
            $this->stream->seek($wholeBlockOffset, $whence);
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new LogicException('Unrecognized whence.');
        }
    }

    /**
     * @param int $length
     * @return string
     */
    public function read($length): string
    {
        // FIXME: (the ciphertext buffer) for some reason, when the stream reads off last bytes, the eof
        //      continues to be false, until another reading occurs, which reads 0 bytes
        while (strlen($this->plaintextBuffer) < $length && !$this->stream->eof()) {
            $ciphertext = $this->readCiphertext(
//                $this->encryptor->getBlockSize() * ceil(($length - strlen($this->plaintextBuffer)) / $this->encryptor->getBlockSize())
                $this->encryptor->getBlockSize()
            );

            // This buffer is a workaround for the problem stated above
            $this->plaintextBuffer .= $this->encryptor->decrypt($ciphertext, $this->stream->eof());
        }

        $data = substr($this->plaintextBuffer, 0, $length);
        $this->plaintextBuffer = substr($this->plaintextBuffer, $length);
        return $data;
    }

    /**
     * @return bool
     */
    public function eof()
    {
        return $this->stream->eof() && empty($this->plaintextBuffer);
    }

    /**
     * @return int|null
     */
    public function getSize()
    {
        if ($this->encryptor->requiresPadding()) {
            return null;
        }

        return $this->stream->getSize();
    }

    /**
     * @return bool
     */
    public function isWritable()
    {
        return false;
    }

    /**
     * @param $length
     * @return string
     */
    private function readCiphertext($length)
    {
        if ($this->ciphertextBuffer === '' && $this->stream->eof()) {
            return '';
        }

        $ciphertext = $this->ciphertextBuffer;

        while (strlen($ciphertext) < $length && !$this->stream->eof()) {
            $ciphertext .= $this->stream->read($length - strlen($ciphertext));
        };

        $this->ciphertextBuffer = $this->stream->read($this->encryptor->getBlockSize());

        return $ciphertext;
    }
}

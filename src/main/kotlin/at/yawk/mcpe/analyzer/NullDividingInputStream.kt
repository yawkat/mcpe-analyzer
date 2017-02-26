package at.yawk.mcpe.analyzer

import java.io.Closeable
import java.io.InputStream
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * @author yawkat
 */
class NullDividingInputStream(inputStream: InputStream, private val bufferSize: Int = 4096) : Closeable by inputStream {
    private val input = inputStream.buffered(bufferSize)
    private val buf = ByteArray(bufferSize)
    private val lock = ReentrantLock()
    private var here: InputStream? = null

    fun next(): InputStream = lock.withLock {
        here?.close()

        val stream = object : InputStream() {
            var done = false

            override fun read(): Int = lock.withLock {
                if (done) return -1
                val next = input.read()
                if (next <= 0) {
                    done = true
                    return -1
                } else {
                    return next
                }
            }

            private fun readToBuffer(len: Int): Int {
                assert(lock.isHeldByCurrentThread)
                if (done) return -1
                val max = Math.min(bufferSize, len)
                input.mark(max)
                val read = input.read(buf, 0, max)
                for (i in 0..read - 1) {
                    if (buf[i].toInt() == 0) {
                        input.reset()
                        input.skip(i + 1L)
                        done = true
                        if (i == 0) return -1
                        return i
                    }
                }
                return read
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int = lock.withLock {
                val n = readToBuffer(len)
                if (n > 0) System.arraycopy(buf, 0, b, off, n)
                return n
            }

            override fun close() = lock.withLock {
                while (readToBuffer(bufferSize) != -1) {
                }
            }
        }
        here = stream
        return stream
    }
}
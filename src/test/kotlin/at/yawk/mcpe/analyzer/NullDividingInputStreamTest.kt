package at.yawk.mcpe.analyzer

import org.testng.Assert.*
import org.testng.annotations.DataProvider
import org.testng.annotations.Test
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets

/**
 * @author yawkat
 */
class NullDividingInputStreamTest {
    @DataProvider
    fun bufferLengths() = listOf(1, 2, 3, 4, 5, 4096).map { arrayOf<Any>(it) }.toTypedArray()

    @Test(dataProvider = "bufferLengths")
    fun `basic read`(bufferLength: Int) {
        val input = "abc\u0000\u0000def\u0000kjfgauksagakugfukvkufvkaugzfzkjgaf\u0000".toByteArray()
        val stream = NullDividingInputStream(ByteArrayInputStream(input), bufferLength)
        assertEquals(stream.next().use { it.readBytes().toString(StandardCharsets.UTF_8) }, "abc")
        assertEquals(stream.next().readBytes().toString(StandardCharsets.UTF_8), "")
        assertEquals(stream.next().use { it.readBytes().toString(StandardCharsets.UTF_8) }, "def")
        assertEquals(stream.next().readBytes().toString(StandardCharsets.UTF_8), "kjfgauksagakugfukvkufvkaugzfzkjgaf")
    }

    @Test(dataProvider = "bufferLengths")
    fun `close skips content`(bufferLength: Int) {
        val input = "abc\u0000\u0000def\u0000kjfgauksagakugfukvkufvkaugzfzkjgaf\u0000".toByteArray()
        val stream = NullDividingInputStream(ByteArrayInputStream(input), bufferLength)
        assertEquals(stream.next().use { it.readBytes().toString(StandardCharsets.UTF_8) }, "abc")
        assertEquals(stream.next().readBytes().toString(StandardCharsets.UTF_8), "")
        stream.next().close()
        assertEquals(stream.next().readBytes().toString(StandardCharsets.UTF_8), "kjfgauksagakugfukvkufvkaugzfzkjgaf")
    }
}
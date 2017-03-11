package at.yawk.mcpe.analyzer

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import org.apache.commons.lang3.StringEscapeUtils
import org.zeroturnaround.exec.ProcessExecutor
import org.zeroturnaround.exec.stream.PumpStreamHandler
import org.zeroturnaround.exec.stream.slf4j.Slf4jStream
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.lang.Long.toHexString
import java.net.URL
import java.nio.file.Path

/**
 * @author yawkat
 */
private fun String.trimEndNewlines(): String {
    var s = this
    while (true) {
        val sizeBefore = s.length
        s = s.trimEnd('\n', '\r')
        if (s.endsWith("<br />")) s = s.substring(0, s.length - 6)
        if (sizeBefore == s.length) return s
    }
}

class R2Pipe constructor(
        private val session: Session
) : Closeable by session {
    private val objectMapper = ObjectMapper()
            .findAndRegisterModules()

    companion object {
        fun open(path: Path) = R2Pipe(ConsoleSession(path.toString()))
    }

    private fun listType(type: Class<*>) = objectMapper.typeFactory.constructCollectionType(List::class.java, type)
    private fun void(cmd: String) = session.cmd(cmd).close()
    private fun text(cmd: String) = session.cmdString(cmd)
    private inline fun <reified R : Any> json(cmd: String): R =
            session.cmdJson(objectMapper.factory, cmd).use {
                objectMapper.readValue(it, R::class.java)
            }

    private inline fun <reified R : Any> jsonList(cmd: String): List<R> =
            session.cmdJson(objectMapper.factory, cmd).use {
                objectMapper.readValue(it, listType(R::class.java))
            }

    ////////////////////

    fun at(
            address: Long? = null,
            architecture: Architecture? = null
    ): R2Pipe = R2Pipe(object : Session {
        fun modulate(cmd: String): String {
            var c = cmd
            if (architecture != null) {
                c += " @a:${architecture.id}"
                if (architecture.bits != null) " @b:${architecture.bits}"
            }
            if (address != null) c += " @ $address"
            return c
        }

        override fun cmd(cmd: String): InputStream {
            return session.cmd(modulate(cmd))
        }

        override fun cmdJson(factory: JsonFactory, cmd: String): JsonParser {
            return session.cmdJson(factory, modulate(cmd))
        }

        override fun cmdString(cmd: String): String {
            return session.cmdString(modulate(cmd))
        }

        override fun close() {
        }
    })

    @JsonIgnoreProperties(ignoreUnknown = true)
    data class Symbol(val name: String, val demname: String, val flagname: String, val size: Int, val vaddr: Long, val paddr: Long)

    fun listSymbols() = jsonList<Symbol>("isj")

    data class Relocation(val name: String?, val type: String, val vaddr: Long, val paddr: Long, val is_ifunc: Boolean)

    fun listRelocations() = jsonList<Relocation>("irj")

    fun seek(obj: String) = void("s $obj")
    fun seek(address: Long) = void("s 0x${toHexString(address)}")
    fun seek(symbol: Symbol) = seek(symbol.vaddr)
    fun analyzeFunction() = void("aF")

    @JsonIgnoreProperties(ignoreUnknown = true)
    data class Instruction(
            val offset: Long,
            @JsonDeserialize(using = EsilCommand.Deserializer::class)
            val esil: List<EsilCommand>?,
            val refptr: Boolean,
            val fcn_addr: Long,
            val fcn_last: Long,
            val size: Int,
            val opcode: String?,
            val bytes: String?,
            val family: String?,
            val type: String?,
            val type_num: Long,
            val type2_num: Long,

            val jump: Long?,
            val fail: Long?,
            val flags: List<String>?
    )

    fun disassemble(n: Int, architecture: Architecture? = null) =
            jsonList<Instruction>("pdj $n ${architecture?.id ?: ""} ${architecture?.bits ?: ""}")

    fun disassemble(architecture: Architecture? = null) =
            disassemble(1, architecture).single()

    fun bytes(n: Int): ByteArray = json("p8j $n")

    fun skip(n: Int = 1) = void("so $n")

    fun initializeVmState() = void("aei")
    fun deinitializeVmState() = void("aei-")
    fun initializeVmStack(start: Long, size: Long) = void("aeim 0x${toHexString(start)} 0x${toHexString(size)}")
    fun deinitializeVmStack(start: Long, size: Long) = void("aeim- 0x${toHexString(start)} 0x${toHexString(size)}")
    fun initializeVmPcHere() = void("aeip")
    fun vmStepUntil(address: Long) = void("aesu 0x${toHexString(address)}")
    fun vmGetRegister(register: String) = java.lang.Long.decode(text("aer $register").trimEndNewlines())!!
    fun enableIoCache() = void("e io.cache=true")
    fun demangle(language: String, symbol: String) = text("iD $language $symbol").trimEndNewlines()

    data class FileInfo(
            val core: Core,
            val bin: Bin
    ) {
        @JsonIgnoreProperties(ignoreUnknown = true)
        data class Core(
                val file: String
        )

        @JsonIgnoreProperties(ignoreUnknown = true)
        data class Bin(
                val arch: String,
                val bits: Int
        )
    }

    fun fileInfo(): FileInfo = json("ij")
}

interface Session : Closeable {
    fun cmd(cmd: String): InputStream
    fun cmdString(cmd: String): String = cmd(cmd).use { it.reader().readText() }
    fun cmdJson(factory: JsonFactory, cmd: String): JsonParser = factory.createParser(cmd(cmd))
}

class ConsoleSession(path: String) : Session {
    val process = ProcessExecutor()
            .command("r2", "-q0", path)
            .destroyOnExit()
            .streams(object : PumpStreamHandler(null, Slf4jStream.of(ConsoleSession::class.java).asError()) {
                // PumpStreamHandler doesn't do what I want...
                override fun setProcessInputStream(os: OutputStream) {
                }
            })
            .start().process!!
    val writer = process.outputStream.bufferedWriter()
    val input = NullDividingInputStream(process.inputStream)

    init {
        input.next().close()
    }

    override fun cmd(cmd: String): InputStream {
        writer.appendln(cmd)
        writer.flush()
        return input.next()
    }

    override fun close() {
        process.destroy()
        process.waitFor()
    }
}

class HttpSession(val host: String) : Session {
    override fun cmdString(cmd: String): String {
        val text = URL("$host/cmd/$cmd").openStream().reader().readText()
        return StringEscapeUtils.unescapeHtml4(text)
    }

    override fun cmdJson(factory: JsonFactory, cmd: String) = factory.createParser(cmdString(cmd))!!
    override fun cmd(cmd: String): InputStream = ByteArrayInputStream(cmdString(cmd).toByteArray())

    override fun close() {
    }
}
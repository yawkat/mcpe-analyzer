package at.yawk.mcpe.analyzer

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import org.zeroturnaround.exec.ProcessExecutor
import org.zeroturnaround.exec.stream.PumpStreamHandler
import org.zeroturnaround.exec.stream.slf4j.Slf4jStream
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.lang.Long.toHexString
import java.net.URL
import java.nio.file.Path

/**
 * @author yawkat
 */
class R2Pipe constructor(
        private val session: Session
) : Closeable by session {
    private val objectMapper = ObjectMapper()
            .findAndRegisterModules()

    companion object {
        fun open(path: Path) = R2Pipe(ConsoleSession(path))
    }

    private fun listType(type: Class<*>) = objectMapper.typeFactory.constructCollectionType(List::class.java, type)
    private fun void(cmd: String) = session.cmd(cmd).close()
    private fun text(cmd: String) = session.cmd(cmd).use { it.reader().readText() }
    private inline fun <reified R : Any> json(cmd: String): R = objectMapper.readValue(session.cmd(cmd), R::class.java)
    private inline fun <reified R : Any> jsonList(cmd: String): List<R> = objectMapper.readValue(session.cmd(cmd), listType(R::class.java))

    ////////////////////

    @JsonIgnoreProperties(ignoreUnknown = true)
    data class Symbol(val name: String, val demname: String, val flagname: String, val size: Int, val vaddr: Long, val paddr: Long)

    fun listSymbols() = jsonList<Symbol>("isj")

    fun seek(obj: String) = void("s $obj")
    fun seek(address: Long) = void("s 0x${toHexString(address)}")
    fun seek(symbol: Symbol) = seek(symbol.vaddr)
    fun analyzeFunction() = void("aF")

    @JsonIgnoreProperties(ignoreUnknown = true)
    data class Instruction(
            val offset: Long,
            @JsonDeserialize(using = EsilCommand.Deserializer::class)
            val esil: List<EsilCommand>,
            val refptr: Boolean,
            val fcn_addr: Long,
            val fcn_last: Long,
            val size: Int,
            val opcode: String,
            val bytes: String,
            val family: String,
            val type: String,
            val type_num: Long,
            val type2_num: Long,

            val jump: Long?,
            val fail: Long?,
            val flags: List<String>?
    )

    fun disassemble(n: Int) = jsonList<Instruction>("pdj $n")
    fun disassemble() = disassemble(1).single()

    fun skip(n: Int = 1) = void("so $n")

    fun initializeVmState() = void("aei")
    fun deinitializeVmState() = void("aei-")
    fun initializeVmStack(start: Long, size: Long) = void("aeim 0x${toHexString(start)} 0x${toHexString(size)}")
    fun deinitializeVmStack(start: Long, size: Long) = void("aeim- 0x${toHexString(start)} 0x${toHexString(size)}")
    fun initializeVmPcHere() = void("aeip")
    fun vmStepUntil(address: Long) = void("aesu 0x${toHexString(address)}")
    fun vmGetRegister(register: String) = java.lang.Long.decode(text("aer $register").trim())!!
    fun enableIoCache() = void("e io.cache=true")
}

interface Session : Closeable {
    fun cmd(cmd: String): InputStream
}

class ConsoleSession(path: Path) : Session {
    val process = ProcessExecutor()
            .command("r2", "-q0", path.toString())
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
    override fun cmd(cmd: String) = URL("$host/cmd/$cmd").openStream()!!

    override fun close() {
    }
}
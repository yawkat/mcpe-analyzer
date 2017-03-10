package at.yawk.mcpe.analyzer.graph

import at.yawk.mcpe.analyzer.Architecture
import at.yawk.mcpe.analyzer.ConsoleSession
import at.yawk.mcpe.analyzer.PipeInfo
import at.yawk.mcpe.analyzer.R2Pipe
import at.yawk.mcpe.analyzer.RegularExpression
import at.yawk.mcpe.analyzer.Session
import at.yawk.mcpe.analyzer.parseRegex
import at.yawk.mcpe.analyzer.simplify
import org.slf4j.LoggerFactory
import org.testng.Assert
import org.testng.annotations.AfterMethod
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import java.util.regex.Pattern

/**
 * @author yawkat
 */
private val log = LoggerFactory.getLogger(FunctionGraphBuilderTest::class.java)

class FunctionGraphBuilderTest {
    var baseSession: Session? = null

    @BeforeMethod
    fun before() {
        baseSession = ConsoleSession("malloc://0x1000")
    }

    @AfterMethod
    fun after() {
        baseSession?.close()
        baseSession = null
    }

    inner class SessionBuilder {
        val session = object : Session {
            override fun cmd(cmd: String) = cmdString(cmd).byteInputStream()

            override fun cmdString(cmd: String): String {
                val result = baseSession!!.cmdString(cmd)
                //log.trace("$ $cmd: $result")
                return result
            }

            override fun close() = baseSession!!.close()
        }
        val pipe = R2Pipe(session)

        val symbols = ArrayList<R2Pipe.Symbol>()
        val pipeInfo = object : PipeInfo(pipe) {
            override val symbols: List<R2Pipe.Symbol>
                get() = this@SessionBuilder.symbols
        }

        fun cmd(cmd: String) {
            session.cmdString(cmd)
        }

        fun put(opcode: String) {
            cmd("wa $opcode")
            pipe.skip()
        }

        fun declare(address: Long, symbol: String) {
            cmd("f $symbol @ $address")
            symbols.add(R2Pipe.Symbol(
                    name = symbol,
                    demname = "",
                    size = 0,
                    flagname = "",
                    paddr = 0,
                    vaddr = address
            ))
        }
    }

    fun test(
            architecture: Architecture,
            expectedRegex: String,
            startAddress: Long,
            terminalCalls: Set<String>,
            initializer: SessionBuilder.() -> Unit
    ) {
        val sessionBuilder = SessionBuilder()

        sessionBuilder.cmd("e asm.arch=" + when (architecture) {
            Architecture.ARM,
            Architecture.THUMB -> "arm"
            Architecture.X86 -> "x86"
        })
        sessionBuilder.cmd("e asm.bits=" + when (architecture) {
            Architecture.ARM -> 32
            Architecture.THUMB -> 16
            Architecture.X86 -> 64
        })

        sessionBuilder.initializer()

        val graph = buildFunctionGraph(sessionBuilder.pipe, sessionBuilder.pipeInfo, { it.symbol.name !in terminalCalls }, Position(startAddress, architecture))
        val regex: RegularExpression<String> = graph.destructiveToRegex().map { call ->
            when (call) {
                is Call.Static -> RegularExpression.Terminal(
                        call.symbol.name + "" + (call.state.registers - architecture.programCounter).entries
                                .joinToString(prefix = "[", separator = ",", postfix = "]", transform = { "${it.key}=${it.value}" })
                )
                Call.Dynamic -> RegularExpression.Terminal("DYN")
                Call.NoReturn -> RegularExpression.nothing<String>()
            }
        }
        log.info(regex.toString())
        Assert.assertEquals(simplify(regex), parseRegex(expectedRegex, Pattern.compile("(DYN|\\w+\\[((\\w+=[0-9a-z]+,)*\\w+=[0-9a-z]+)?])")))
    }

    @Test
    fun `empty`() = test(
            architecture = Architecture.X86,
            expectedRegex = "",
            startAddress = 0,
            terminalCalls = emptySet()
    ) {
        put("ret")
    }

    @Test
    fun `simple call`() = test(
            architecture = Architecture.X86,
            expectedRegex = "abc[]",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("call abc")
        put("ret")
    }

    @Test
    fun `loop branch up`() = test(
            architecture = Architecture.X86,
            expectedRegex = "abc[]+",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("call abc")
        put("je 0")
        put("ret")
    }

    @Test
    fun `loop branch down`() = test(
            architecture = Architecture.X86,
            expectedRegex = "abc[]?",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("je 0xb")
        put("call abc")
        put("ret")
    }

    @Test
    fun `simple parameter`() = test(
            architecture = Architecture.X86,
            expectedRegex = "abc[rax=0]",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("mov rax, 0")
        put("call abc")
        put("ret")
    }

    @Test
    fun `simple parameter with revisit`() = test(
            architecture = Architecture.X86,
            expectedRegex = "abc[]+",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("mov rax, 0")
        put("call abc")
        put("mov rax, 1")
        put("je 7")
        put("ret")
    }

    @Test
    fun `dynamic call and normal call`() = test(
            architecture = Architecture.X86,
            expectedRegex = "DYN abc[]",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("call ebx")
        put("call abc")
        put("ret")
    }

    @Test
    fun `tail dynamic call`() = test(
            architecture = Architecture.X86,
            expectedRegex = "DYN",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("jmp ebx")
        put("call abc")
        put("ret")
    }

    @Test
    fun `enter call`() = test(
            architecture = Architecture.X86,
            expectedRegex = "abc[]{2}",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("call 50")
        put("call abc")
        put("ret")
        pipe.seek(50)
        put("jmp abc")
    }

    @Test
    fun `noreturn call`() = test(
            architecture = Architecture.X86,
            expectedRegex = "∅",
            startAddress = 0,
            terminalCalls = emptySet()
    ) {
        declare(100, "imp.__assert_rtn")

        put("call imp.__assert_rtn")
    }

    @Test
    fun `noreturn jmp`() = test(
            architecture = Architecture.X86,
            expectedRegex = "∅",
            startAddress = 0,
            terminalCalls = emptySet()
    ) {
        declare(100, "imp.__assert_rtn")

        put("jmp imp.__assert_rtn")
    }

    @Test
    fun `ujmp predict`() = test(
            architecture = Architecture.X86,
            expectedRegex = "abc[rax=100]",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("mov eax, 100")
        put("call eax")
        put("ret")
    }

    @Test
    fun `ujmp mem`() = test(
            architecture = Architecture.X86,
            expectedRegex = "abc[rax=100]",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("mov eax, 0")
        put("mov rax, dword [eax + 50]")
        put("call rax")
        put("ret")

        cmd("wx 64 @ 50")
    }

    @Test
    fun `arithmetic jump`() = test(
            architecture = Architecture.ARM,
            expectedRegex = "abc[]",
            startAddress = 0,
            terminalCalls = setOf("abc")
    ) {
        declare(100, "abc")

        put("add pc, 92")
        put("ret")
    }

    @Test
    fun `illegal jump`() = test(
            architecture = Architecture.X86,
            expectedRegex = "DYN",
            startAddress = 0,
            terminalCalls = setOf()
    ) {
        put("call 100")
        put("ret")

        cmd("wx ffff @ 100")
    }
}
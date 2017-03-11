package at.yawk.mcpe.analyzer

import at.yawk.mcpe.analyzer.graph.Call
import at.yawk.mcpe.analyzer.graph.Position
import com.beust.jcommander.JCommander
import com.beust.jcommander.Parameter
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.slf4j.MarkerFactory
import java.io.Closeable
import java.io.InputStream
import java.util.HashMap
import java.util.TreeSet
import java.util.regex.Pattern

/**
 * @author yawkat
 */
private val log = LoggerFactory.getLogger(DisassemblerX86::class.java)

private class Args {
    @Parameter(arity = 1)
    lateinit var file: List<String>
}

fun main(argsArray: Array<String>) {
    val args = Args()
    JCommander(args, *argsArray)

    val session = when {
        args.file.single().startsWith("http") -> HttpSession(args.file.single())
        else -> ConsoleSession(args.file.single())
    }

    val pipe = R2Pipe(object : Session, Closeable by session {
        val TAG = MarkerFactory.getMarker("commandLog")

        override fun cmd(cmd: String): InputStream {
            log.trace(TAG, "$ $cmd")
            return session.cmd(cmd)
        }

        override fun cmdJson(factory: JsonFactory, cmd: String): JsonParser {
            log.trace(TAG, "$ $cmd")
            return session.cmdJson(factory, cmd)
        }

        override fun cmdString(cmd: String): String {
            log.trace(TAG, "$ $cmd")
            return session.cmdString(cmd)
        }
    })
    val disassembler = DisassemblerX86(pipe)
    val (packetSignatures, typeSignatures) = /*emptyMap<String, String>() to emptyMap<String, String>()  */disassembler.collectPacketSignatures()
    val packetIds = /*emptyMap<String, Int>()*/disassembler.collectPacketIds()

    data class Packet(
            val id: String?, // hex string
            val name: String,
            val signature: String?
    )

    val packetNames = packetIds.keys + packetSignatures.keys
    val packets = packetNames.map { name ->
        Packet(
                name = name,
                id = packetIds[name]?.let { id -> String.format("%02x", id) },
                signature = packetSignatures[name]
        )
    }.sortedBy { it.id }

    ObjectMapper()
            .writerWithDefaultPrettyPrinter()
            .writeValue(System.out, mapOf(
                    Pair("packets", packets),
                    Pair("types", typeSignatures)
            ))
}

private class DisassemblerX86(val pipe: R2Pipe) {
    private val pipeInfo = PipeInfo(pipe)

    fun collectPacketSignatures(): Signatures {
        val ignoredCalls = TreeSet<String>()

        fun removeComponents(fancyName: String, component: String): String {
            var fancyName1 = fancyName
            while (fancyName1.contains(",$component<")) {
                val start = fancyName1.indexOf(",$component<")
                var i = start + ",$component<".length
                var depth = 1
                while (depth > 0) {
                    if (fancyName1[i] == '<') depth++
                    if (fancyName1[i] == '>') depth--
                    i++
                }
                fancyName1 = fancyName1.substring(0, start) + fancyName1.substring(i)
            }
            return fancyName1
        }

        fun visitFunction(name: String, address: Long): RegularExpression<String> {
            fun symbolToTerminal(state: EsilState, symbol: R2Pipe.Symbol): RegularExpression<String>? {
                var dname = symbol.demname
                if (dname.isEmpty()) {
                    // iD doesn't work because of r2 bug
                    //dname = pipe.demangle("cxx", symbol.name) // yes, this works sometimes for some reason
                    //log.trace("Trying harder to demangle ${symbol.name} -> '$dname'")
                    if (dname.isEmpty()) dname = symbol.name
                }
                val matcher = Pattern.compile("BinaryStream::write(.*)").matcher(dname)
                if (matcher.matches()) {
                    var fancyName = matcher.group(1).replace("std::__1::", "")
                    fancyName = removeComponents(fancyName, "allocator")
                    fancyName = removeComponents(fancyName, "default_delete")
                    if (fancyName.startsWith("Type<"))
                        fancyName = fancyName.substring("Type<".length, fancyName.length - 1)
                    return RegularExpression.Terminal(fancyName)
                } else when (dname) {
                    "Tag::writeNamedTag" -> return RegularExpression.Terminal("NamedTag")
                    "PlayerListEntry::write" -> return RegularExpression.Terminal("PlayerListEntry")
                    "CraftingDataEntry::write" -> return RegularExpression.Terminal("CraftingDataEntry")
                    "imp._ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm" ->
                        return RegularExpression.Terminal("RAW(${state.registers["rdx"] ?: "?"})")
                    else -> {
                        ignoredCalls.add(dname)
                        return null
                    }
                }
            }

            fun shouldEnterCall(call: Call.Static): Boolean {
                if (call.symbol.name.startsWith("imp.")) return false
                if (call.symbol.name.endsWith("8toStringEv")) return false
                if (call.symbol.name == "__ZNK12ItemInstance22getStrippedNetworkItemEv") return false
                return symbolToTerminal(call.state, call.symbol) == null
            }

            val automaton = at.yawk.mcpe.analyzer.graph.buildFunctionGraph(pipe, pipeInfo, enterCall = ::shouldEnterCall, position = Position(address, pipeInfo.architecture))
            val regex = automaton.destructiveToRegex()
            val mapped = regex.map { call ->
                when (call) {
                    is at.yawk.mcpe.analyzer.graph.Call.Static ->
                        symbolToTerminal(call.state, call.symbol) ?: RegularExpression.empty()
                    is at.yawk.mcpe.analyzer.graph.Call.Dynamic -> RegularExpression.Terminal("DYN")
                    is at.yawk.mcpe.analyzer.graph.Call.NoReturn -> RegularExpression.nothing()
                }
            }
            log.debug("raw $name: $mapped")
            return simplify(mapped)
        }

        val packetSignatures = HashMap<String, String>()
        val typeSignatures = HashMap<String, String>()

        for (method in pipeInfo.symbols) {
            val packetWriteMatcher = Pattern.compile("(.*)Packet::write").matcher(method.demname)
            if (packetWriteMatcher.matches()) {
                val name = packetWriteMatcher.group(1)
                packetSignatures[name] = try {
                    regexToString(visitFunction(name, method.vaddr))
                } catch (e: Throwable) {
                    log.warn("Failure in $name", e)
                    "ERROR"
                }
            }

            val typeWriteMatcher = Pattern.compile("BinaryStream::write(.+)").matcher(method.demname)
            if (typeWriteMatcher.matches()) {
                val name = typeWriteMatcher.group(1)
                typeSignatures[name] = try {
                    regexToString(visitFunction(name, method.vaddr))
                } catch (e: Throwable) {
                    log.warn("Failure in $name", e)
                    "ERROR"
                }
            }
        }

        for (ignoredCall in ignoredCalls) {
            log.info("Ignoring call symbol $ignoredCall")
        }

        return Signatures(packetSignatures , typeSignatures)
    }

    data class Signatures(
            val packetSignatures: Map<String, String>,
            val typeSignatures: Map<String, String>
    )

    fun collectPacketIds(): Map<String, Int> {
        val packetIds = HashMap<String, Int>()

        pipe.enableIoCache()

        for (symbol in pipeInfo.symbols) {
            val packetWriteMatcher = Pattern.compile("(.*)Packet::getId").matcher(symbol.demname)
            if (!packetWriteMatcher.matches()) continue
            val name = packetWriteMatcher.group(1)
            log.debug("Reading packet ID for {}", name)

            pipe.seek(symbol)
            pipe.analyzeFunction()
            val end = pipe.disassemble().fcn_last

            pipe.initializeVmState()
            pipe.initializeVmStack(0x2000, 0xffff)
            try {
                pipe.initializeVmPcHere()
                pipe.at(architecture = pipeInfo.architecture).vmStepUntil(end)

                packetIds[name] = pipe.vmGetRegister(pipeInfo.architecture.returnRegister).toInt()
            } finally {
                pipe.deinitializeVmStack(0x2000, 0xffff)
                pipe.deinitializeVmState()
            }
        }

        return packetIds
    }
}

private fun regexToString(outermost: RegularExpression<String>): String {
    val LEVEL_TOP = 0
    val LEVEL_UNION = 1
    val LEVEL_CONCAT = 2
    val LEVEL_REPEAT = 3
    val LEVEL_TERMINAL = 4

    val builder = StringBuilder()
    fun work(ex: RegularExpression<String>, parentLevel: Int): Unit {
        val ourLevel = when (ex) {
            is RegularExpression.Concatenate -> LEVEL_CONCAT
            is RegularExpression.Or -> LEVEL_UNION
            is RegularExpression.Repeat -> LEVEL_REPEAT
            is RegularExpression.Terminal -> LEVEL_TERMINAL
            else -> throw AssertionError()
        }
        if (parentLevel > ourLevel) builder.append('(')
        when (ex) {
            is RegularExpression.Concatenate -> ex.members.forEachIndexed { i, child ->
                if (i > 0) builder.append(' ')
                work(child, ourLevel)
            }
            is RegularExpression.Or -> ex.alternatives.forEachIndexed { i, child ->
                if (i > 0) builder.append(" | ")
                work(child, ourLevel)
            }
            is RegularExpression.Repeat -> {
                work(ex.expression, ourLevel)
                builder.append(ex.suffix)
            }
            is RegularExpression.Terminal -> builder.append(ex.value)
        }
        if (parentLevel > ourLevel) builder.append(')')
    }
    work(outermost, LEVEL_TOP)
    return builder.toString()
}
package at.yawk.mcpe.analyzer

import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.commons.lang3.StringEscapeUtils
import org.slf4j.LoggerFactory
import java.io.InputStream
import java.nio.file.Paths
import java.util.HashMap
import java.util.TreeSet
import java.util.regex.Pattern

/**
 * @author yawkat
 */
private val log = LoggerFactory.getLogger(DisassemblerX86::class.java)

private fun usage(): Nothing {
    System.err.println("Usage: java -jar <file> <r2 server URL | file>")
    System.exit(-1)
    throw AssertionError()
}

fun main(args: Array<String>) {
    if (args.size != 1) usage()
    val session = when {
        args[0].startsWith("http") -> HttpSession(args[0])
        else -> ConsoleSession(Paths.get(args[0]))
    }

    val pipe = R2Pipe(object : Session by session {
        override fun cmd(cmd: String): InputStream {
            log.trace("$ $cmd")
            return session.cmd(cmd)
        }
    })
    val disassembler = DisassemblerX86(pipe)
    val (packetSignatures, typeSignatures) = disassembler.collectPacketSignatures()
    val packetIds = disassembler.collectPacketIds()

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
    private val symbols: List<R2Pipe.Symbol> by lazy { pipe.listSymbols() }

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

        fun visitFunction(name: String): RegularExpression<String> {
            fun callToTerminal(call: Call) = if (call is Call.Fixed) {
                val symbol = symbols.find { it.vaddr == call.address }!!
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
                    RegularExpression.Terminal(fancyName)
                } else when (dname) {
                    "Tag::writeNamedTag" -> RegularExpression.Terminal("NamedTag")
                    "PlayerListEntry::write" -> RegularExpression.Terminal("PlayerListEntry")
                    "CraftingDataEntry::write" -> RegularExpression.Terminal("CraftingDataEntry")
                    "imp._ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm" ->
                        RegularExpression.Terminal("RAW(${call.registerGuesses["rdx"] ?: "?"})")
                    else -> {
                        ignoredCalls.add(dname)
                        RegularExpression.empty<String>()
                    }
                }
            } else {
                RegularExpression.Terminal("DYN")
            }

            val regex = buildFunctionGraph(pipe, enterCall = { call->
                callToTerminal(call) == RegularExpression.empty<String>()
            })
            val mapped = regex.map(::callToTerminal)
            log.debug("raw $name: $mapped")
            return simplify(mapped)
        }

        val packetSignatures = HashMap<String, String>()
        val typeSignatures = HashMap<String, String>()

        for (method in symbols) {
            val packetWriteMatcher = Pattern.compile("(.*)Packet::write").matcher(method.demname)
            if (packetWriteMatcher.matches()) {
                pipe.seek(method)
                val name = packetWriteMatcher.group(1)
                packetSignatures[name] = try {
                    regexToString(visitFunction(name))
                } catch (e: Throwable) {
                    log.warn("Failure in $name", e)
                    "ERROR"
                }
            }

            val typeWriteMatcher = Pattern.compile("BinaryStream::writeType<(.*)>").matcher(method.demname)
            if (typeWriteMatcher.matches()) {
                pipe.seek(method)
                val name = typeWriteMatcher.group(1)
                typeSignatures[name] = try {
                    regexToString(visitFunction(name))
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

        for (symbol in symbols) {
            val packetWriteMatcher = Pattern.compile("(.*)Packet::getId").matcher(symbol.demname)
            if (!packetWriteMatcher.matches()) continue
            val name = packetWriteMatcher.group(1)

            pipe.seek(symbol)
            pipe.analyzeFunction()
            val end = pipe.disassemble().fcn_last

            pipe.initializeVmState()
            pipe.initializeVmStack(0x2000, 0xffff)
            try {
                pipe.initializeVmPcHere()
                pipe.vmStepUntil(end)

                packetIds[name] = pipe.vmGetRegister("eax").toInt()
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
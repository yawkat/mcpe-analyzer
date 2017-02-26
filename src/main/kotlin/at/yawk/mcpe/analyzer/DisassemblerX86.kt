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
    val packetSignatures = disassembler.collectPacketSignatures()
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
                    Pair("packets", packets)
            ))
}

private class DisassemblerX86(val pipe: R2Pipe) {
    private val symbols: List<R2Pipe.Symbol> by lazy { pipe.listSymbols() }

    fun collectPacketSignatures(): Map<String, String> {
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
            val regex = buildFunctionGraph(pipe)
            val mapped = regex.map { call ->
                if (call is Call.Fixed) {
                    val symbol = symbols.find { it.vaddr == call.address }!!
                    val demangledName = StringEscapeUtils.unescapeHtml4(symbol.demname)
                    val matcher = Pattern.compile("BinaryStream::write(.*)").matcher(demangledName)
                    if (matcher.matches()) {
                        var fancyName = matcher.group(1).replace("std::__1::", "")
                        fancyName = removeComponents(fancyName, "allocator")
                        fancyName = removeComponents(fancyName, "default_delete")
                        if (fancyName.startsWith("Type<"))
                            fancyName = fancyName.substring("Type<".length, fancyName.length - 1)
                        RegularExpression.Terminal(fancyName)
                    } else when (symbol.demname) {
                        "Tag::writeNamedTag" -> RegularExpression.Terminal("NamedTag")
                        "PlayerListEntry::write" -> RegularExpression.Terminal("PlayerListEntry")
                        "CraftingDataEntry::write" -> RegularExpression.Terminal("CraftingDataEntry")
                        else -> {
                            ignoredCalls.add(if (symbol.demname.isEmpty()) symbol.name else symbol.demname)
                            RegularExpression.empty<String>()
                        }
                    }
                } else {
                    RegularExpression.Terminal("DYN")
                }
            }
            log.debug("raw $name: $mapped")
            return simplify(mapped)
        }

        val packetSignatures = HashMap<String, String>()

        for (method in symbols) {
            val packetWriteMatcher = Pattern.compile("(.*)Packet::write").matcher(method.demname)
            if (!packetWriteMatcher.matches()) continue
            pipe.seek(method)
            val name = packetWriteMatcher.group(1)
            packetSignatures[name] = try {
                regexToString(visitFunction(name))
            } catch (e: Throwable) {
                log.warn("Failure in $name", e)
                "ERROR"
            }
        }

        for (ignoredCall in ignoredCalls) {
            log.info("Ignoring call symbol $ignoredCall")
        }

        return packetSignatures
    }

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
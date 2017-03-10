package at.yawk.mcpe.analyzer.graph

import at.yawk.mcpe.analyzer.EsilEnvironment
import at.yawk.mcpe.analyzer.EsilState
import at.yawk.mcpe.analyzer.PipeInfo
import at.yawk.mcpe.analyzer.R2Pipe
import at.yawk.mcpe.analyzer.debug
import at.yawk.mcpe.analyzer.hex
import at.yawk.mcpe.analyzer.interpretEsilInstruction
import at.yawk.mcpe.analyzer.trace
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * @author yawkat
 */
private val log = LoggerFactory.getLogger(InstructionParser::class.java)

internal fun computeTransitions(
        pipe: R2Pipe,
        pipeInfo: PipeInfo,

        position: Position,
        insn: R2Pipe.Instruction,
        state: EsilState
): List<InstructionTransition> {
    val parser = InstructionParser(pipe, pipeInfo, position, insn, state)
    val transitions = parser.computeTransitions()
    log.trace {
        "$position: ${insn.opcode?.padEnd(30)} ${parser.state} -> $transitions"
    }
    return transitions
}

internal fun R2Pipe.Instruction.isIllegal() = type == null || type == "ill" || type == "invalid"

private fun <T> lazyNotThreadSafe(initializer: () -> T) = lazy(LazyThreadSafetyMode.NONE, initializer)

private class InstructionParser(
        val pipe: R2Pipe,
        val pipeInfo: PipeInfo,
        val position: Position,

        val insn: R2Pipe.Instruction,
        state: EsilState
) {
    val state = state.copy(state.registers + (position.architecture.programCounter to position.architecture.getPc(insn)))

    val nextState by lazyNotThreadSafe {
        try {
            interpretEsilInstruction(this.state, insn.esil!!, environment = Env())
        } catch (e: Exception) {
            log.warn("ESIL evaluation failed: $insn", e)
            EsilState.UNKNOWN
        }
    }

    val jumpDestination: Destination by lazyNotThreadSafe {
        if (insn.jump != null) {
            val (addr, arch) = position.architecture.getJumpTarget(insn.jump, insn)
            Destination.Known(Position(addr, arch))
        } else {
            val targetFromPc = nextState.registers[position.architecture.programCounter]
            if (targetFromPc == null) {
                log.debug { "Cannot predict ujmp/ucall target for $position $insn with vm state $state -> $nextState" }
                Destination.Unknown
            } else {
                val (address, arch) = position.architecture.getJumpTarget(targetFromPc, insn)
                Destination.Known(Position(address, arch))
            }
        }
    }

    val nextDestination by lazyNotThreadSafe {
        Destination.Known(position.copy(address = position.address + insn.size))
    }

    fun computeTransitions(): List<InstructionTransition> {
        if (insn.isIllegal())
            throw Exception("illegal instruction at $position")

        val type = insn.type!!

        if (type.matches("u?c?(call|jmp)".toRegex())) {
            var transitions = emptyList<InstructionTransition>()
            if (type.matches("c(call|jmp)".toRegex())) {
                transitions += InstructionTransition.Jump(nextState, nextDestination)
            }
            if (type.matches("u?c?call".toRegex())) {
                transitions += InstructionTransition.Call(nextState, jumpDestination, nextDestination)
            } else {
                transitions += InstructionTransition.Jump(nextState, jumpDestination)
            }

            return transitions
        }

        if (type.matches("c?ret".toRegex())) {
            var transitions = emptyList<InstructionTransition>()
            if (type == "cret") {
                transitions += InstructionTransition.Jump(nextState, nextDestination)
            }
            transitions += InstructionTransition.Return

            return transitions
        }

        if (type.matches(".*(jmp|call)".toRegex())) {
            TODO("$position: $type $insn")
        }

        val computedPc = nextState.registers[position.architecture.programCounter]
        if (state.registers[position.architecture.programCounter] != computedPc) {
            if (computedPc == null) {
                return listOf(InstructionTransition.Jump(nextState, Destination.Unknown))
            } else {
                val (tgtPc, tgtArch) = position.architecture.getArithmeticJumpTarget(computedPc)
                val tgt = Position(tgtPc, tgtArch)
                log.debug { "Arithmetic jump $position -> $tgt" }
                return listOf(InstructionTransition.Jump(nextState, Destination.Known(tgt)))
            }
        }

        return listOf(InstructionTransition.Jump(nextState, nextDestination))
    }

    private inner class Env : EsilEnvironment {
        override val currentAddress = position.address
        override fun load(address: Long, bytes: Int?): Long {
            val bytesNonNull = bytes ?: position.architecture.wordSize
            if (bytesNonNull == position.architecture.wordSize) {
                val relocation = pipeInfo.relocationAtAddress(address)
                if (relocation != null) {
                    log.trace { "Load: following relocation at address 0x${address.hex()} with name ${relocation.name}" }

                    if (relocation.name == "__stack_chk_guard") {
                        return 0
                    }

                    val symbol = pipeInfo.symbolForName(relocation.name!!)!!
                    return pipeInfo.architecture.mapRelocationEntry(symbol.vaddr)
                }
            }

            val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            buf.put(pipe.at(address).bytes(bytesNonNull))
            buf.position(0)
            val value = buf.long
            log.trace { "Load 0x${address.hex()}:$bytes -> 0x${value.hex()}" }
            return value
        }

        override fun mask(value: Long) = value and position.architecture.wordMask

        override fun translateRegister(name: String): String = position.architecture.translateRegister(name)
    }
}

internal sealed class InstructionTransition {
    object Return : InstructionTransition()
    data class Jump(val state: EsilState, val target: Destination) : InstructionTransition()
    data class Call(val state: EsilState, val target: Destination, val returnPosition: Destination.Known) : InstructionTransition()
}

internal sealed class Destination {
    object Unknown : Destination()
    data class Known(val position: Position) : Destination()
}
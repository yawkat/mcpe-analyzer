package at.yawk.mcpe.analyzer

import javafx.scene.shape.Arc

/**
 * @author yawkat
 */
enum class Architecture(
        val returnRegister: String,
        val programCounter: String,
        val wordSize: Int,

        val id: String,
        val bits: Int?
) {
    ARM(
            returnRegister = "r0",
            programCounter = "pc",
            wordSize = 4,
            id = "arm",
            bits = 32
    ) {
        override fun getPc(insn: R2Pipe.Instruction) = insn.offset + 8
        override fun getArithmeticJumpTarget(target: Long): Pair<Long, Architecture> {
            if (target and 0x80000000 != 0L) {
                return target and 0x7fffffff to THUMB
            }
            return super.getArithmeticJumpTarget(target)
        }
    },
    THUMB(
            returnRegister = "r0",
            programCounter = "pc",
            wordSize = 4,
            id = "arm",
            bits = 16
    ) {
        override fun getPc(insn: R2Pipe.Instruction) = insn.offset + 4
        override fun getJumpTarget(target: Long, insn: R2Pipe.Instruction): Pair<Long, Architecture> {
            // bx, blx, etc
            if (insn.opcode!!.matches("\\w+x.*".toRegex()) && (target and 0x80000000).toInt() == 0) return target to ARM
            return super.getJumpTarget(target, insn)
        }

        override fun getArithmeticJumpTarget(target: Long): Pair<Long, Architecture> {
            return super.getArithmeticJumpTarget(target and 0x7fffffff)
        }

        override fun mapRelocationEntry(target: Long) = target or 0x80000000
    },
    X86(
            returnRegister = "rax",
            programCounter = "rip",
            wordSize = 8, // todo
            id = "x86",
            bits = null
    ) {
        override fun getPc(insn: R2Pipe.Instruction): Long = insn.offset + insn.size

        override fun translateRegister(name: String): String = when {
            name.matches("e[a-z]{2}".toRegex()) -> "r" + name.substring(1)
            else -> name
        }
    };

    val wordMask = (-1L shl (wordSize * 8 - 1) shl 1).inv()

    open fun getPc(insn: R2Pipe.Instruction) = insn.offset
    open fun mapRelocationEntry(target: Long) = target

    open fun getJumpTarget(target: Long, insn: R2Pipe.Instruction) = getArithmeticJumpTarget(target)
    open fun getArithmeticJumpTarget(target: Long) = target and wordMask to this

    open fun translateRegister(name: String): String = name

    companion object {
        fun of(pipe: R2Pipe): Architecture {
            val bin = pipe.fileInfo().bin
            return when (bin.arch) {
                "arm" -> when (bin.bits) {
                    16 -> THUMB
                    32 -> ARM
                    else -> throw UnsupportedOperationException("arm " + bin.bits)
                }
                "x86" -> X86
                else -> throw UnsupportedOperationException(bin.arch)
            }
        }
    }
}
package at.yawk.mcpe.analyzer

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import java.io.IOException
import java.util.ArrayList

/**
 * @author yawkat
 */
interface EsilCommand {
    companion object {
        fun parse(esil: String): List<EsilCommand> {
            var i = 0

            fun take(): String? {
                if (i >= esil.length) return null
                var end = esil.indexOf(',', startIndex = i)
                if (end == -1) end = esil.length
                val cmd = esil.substring(i, end)
                i = end + 1
                return cmd
            }

            fun takeUntil(until: String?): List<EsilCommand> {
                val result = ArrayList<EsilCommand>()
                while (true) {
                    val next = take()
                    if (next == until) return result
                    if (next == null) throw IOException("Invalid ESIL: $esil")
                    val insn = if (next == "?{") Conditional(takeUntil("}")) else parseSingle(next)
                    result.add(insn)
                }
            }

            return takeUntil(null)
        }

        private fun parseSingle(insn: String): EsilCommand {
            @Suppress("LoopToCallChain")
            for (operation in Operation.values()) {
                if (operation.code == insn) return operation
            }

            try {
                return Value(insn.toInt())
            } catch (e: NumberFormatException) {}

            return Register(insn)
        }
    }

    data class Register(val name: String) : EsilCommand

    data class Value(val value: Int) : EsilCommand

    data class Conditional(val body: List<EsilCommand>) : EsilCommand

    enum class Operation(val code: String) : EsilCommand {
        TRAP("TRAP"),
        SYSCALL("$"),
        CURRENT_ADDRESS("$$"),
        COMPARE("=="),
        LESS_THAN("<"),
        LESS_THAN_EQUAL("<="),
        GREATER_THAN(">"),
        GREATER_THAN_EQUAL(">="),
        SHIFT_LEFT("<<"),
        SHIFT_RIGHT(">>"),
        ROTATE_LEFT("<<<"),
        ROTATE_RIGHT(">>>"),
        AND("&"),
        OR("`"),
        XOR("^"),
        ADD("+"),
        SUB("-"),
        MUL("*"),
        DIV("/"),
        MOD("%"),
        NEG("!"),
        INC("++"),
        DEC("--"),
        ADD_REGISTER("+="),
        SUB_REGISTER("-="),
        MUL_REGISTER("*="),
        DIV_REGISTER("/="),
        MOD_REGISTER("%="),
        SHIFT_LEFT_REGISTER("<<="),
        AND_REGISTER("&="),
        OR_REGISTER("`="),
        XOR_REGISTER("^="),
        INC_REGISTER("++="),
        DEC_REGISTER("--="),
        NOT_REGISTER("!="),
        SWAP("SWAP"),
        PICK("PICK"),
        RPICK("RPICK"),
        DUP("DUP"),
        NUM("NUM"),
        CLEAR("CLEAR"),
        BREAK("BREAK"),
        TODO("TODO"),
        ASSIGN("="),

        STORE("=[]"),
        STORE_MULTI("=[*]"),
        STORE_BYTE("=[1]"),
        STORE_HALF("=[2]"),
        LOAD("=[]"),
        LOAD_MULTI("=[*]"),
        LOAD_BYTE("=[1]"),
        LOAD_HALF("=[2]"),
    }

    class Deserializer : JsonDeserializer<List<EsilCommand>>() {
        override fun deserialize(p: JsonParser, ctxt: DeserializationContext) = parse(p.valueAsString)
    }
}
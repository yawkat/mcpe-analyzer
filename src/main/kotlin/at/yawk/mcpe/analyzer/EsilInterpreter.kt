package at.yawk.mcpe.analyzer

import org.slf4j.LoggerFactory
import java.util.ArrayDeque
import java.util.HashMap

/**
 * @author yawkat
 */
private val log = LoggerFactory.getLogger(EsilInterpreter::class.java)

data class EsilState(
        val registers: Map<String, Long>
) {
    companion object {
        val UNKNOWN = EsilState(emptyMap())

        /**
         * Construct a new [EsilState] containing the state that the same in both given states.
         */
        fun intersection(a: EsilState, b: EsilState) = EsilState(
                registers = a.registers.filter { b.registers[it.key] == it.value }
        )
    }
}

private sealed class StackValue {
    object Unknown : StackValue()
    class Numeric(val value: Long) : StackValue()
    class Register(val name: String): StackValue()
}

fun interpretEsilInstruction(
        stateBefore: EsilState,
        instruction: List<EsilCommand>
): EsilState {
    val interpreter = EsilInterpreter(stateBefore)
    instruction.forEach { interpreter.eval(it) }
    return interpreter.state
}

private class EsilInterpreter(var state: EsilState) {
    val stack = ArrayDeque<StackValue>()

    fun getValue(stackValue: StackValue): Long? = when (stackValue) {
        StackValue.Unknown -> null
        is StackValue.Numeric -> stackValue.value
        is StackValue.Register -> state.registers[stackValue.name]
    }

    fun setRegister(register: String, value: Long?) {
        if (value == null) {
            val new = HashMap(state.registers)
            new.remove(register)
            state = EsilState(new)
        } else {
            state = state.copy(registers = state.registers + (register to value))
        }
    }

    fun eval(cmd: EsilCommand) {
        log.trace("{} -> {}", cmd, stack)

        when (cmd) {
            is EsilCommand.Register -> stack.push(StackValue.Register(cmd.name))
            is EsilCommand.Value -> stack.push(StackValue.Numeric(cmd.value))
            is EsilCommand.Label -> stack.push(StackValue.Unknown)
            is EsilCommand.Conditional -> {
                val before = state
                cmd.body.forEach { eval(it) }
                val after = state
                // only keep values that are unchanged in the body
                state = EsilState.intersection(before, after)
            }
            is EsilCommand.Operation -> when (cmd) {
                EsilCommand.Operation.TRAP,
                EsilCommand.Operation.SYSCALL
                -> stack.pop()
                EsilCommand.Operation.CURRENT_ADDRESS -> {
                    stack.push(StackValue.Unknown)
                }
                EsilCommand.Operation.COMPARE,
                EsilCommand.Operation.LESS_THAN,
                EsilCommand.Operation.LESS_THAN_EQUAL,
                EsilCommand.Operation.GREATER_THAN,
                EsilCommand.Operation.GREATER_THAN_EQUAL,
                EsilCommand.Operation.SHIFT_LEFT,
                EsilCommand.Operation.SHIFT_RIGHT,
                EsilCommand.Operation.ROTATE_LEFT,
                EsilCommand.Operation.ROTATE_RIGHT,
                EsilCommand.Operation.AND,
                EsilCommand.Operation.OR,
                EsilCommand.Operation.XOR,
                EsilCommand.Operation.ADD,
                EsilCommand.Operation.SUB,
                EsilCommand.Operation.MUL,
                EsilCommand.Operation.DIV,
                EsilCommand.Operation.MOD
                -> {
                    stack.pop()
                    stack.pop()
                    stack.push(StackValue.Unknown)
                }
                EsilCommand.Operation.INC,
                EsilCommand.Operation.DEC,
                EsilCommand.Operation.NEG
                -> {
                    stack.pop()
                    stack.push(StackValue.Unknown)
                }
                EsilCommand.Operation.ADD_REGISTER,
                EsilCommand.Operation.SUB_REGISTER,
                EsilCommand.Operation.MUL_REGISTER,
                EsilCommand.Operation.DIV_REGISTER,
                EsilCommand.Operation.MOD_REGISTER,
                EsilCommand.Operation.SHIFT_LEFT_REGISTER,
                EsilCommand.Operation.SHIFT_RIGHT_REGISTER,
                EsilCommand.Operation.AND_REGISTER,
                EsilCommand.Operation.OR_REGISTER,
                EsilCommand.Operation.XOR_REGISTER
                -> {
                    val reg = stack.pop() as StackValue.Register
                    stack.pop()
                    setRegister(reg.name, null)
                }
                EsilCommand.Operation.INC_REGISTER,
                EsilCommand.Operation.DEC_REGISTER,
                EsilCommand.Operation.NOT_REGISTER
                -> {
                    val reg = stack.pop() as StackValue.Register
                    setRegister(reg.name, null)
                }
                EsilCommand.Operation.SWAP -> {
                    val a = stack.pop()
                    val b = stack.pop()
                    stack.push(a)
                    stack.push(b)
                }
                EsilCommand.Operation.DUP -> {
                    stack.push(stack.peekFirst())
                }
                EsilCommand.Operation.NUM -> {
                    stack.push(getValue(stack.pop())?.let { StackValue.Numeric(it) } ?: StackValue.Unknown)
                }
                EsilCommand.Operation.ASSIGN -> {
                    val reg = stack.pop() as StackValue.Register
                    val v = stack.pop()
                    setRegister(reg.name, getValue(v))
                }
                EsilCommand.Operation.STORE,
                EsilCommand.Operation.STORE_BYTE,
                EsilCommand.Operation.STORE_INT,
                EsilCommand.Operation.STORE_HALF,
                EsilCommand.Operation.STORE_LONG -> {
                    stack.pop()
                    stack.pop()
                }
                EsilCommand.Operation.STORE_MULTI -> {
                    val n = getValue(stack.pop())!!
                    for (i in 1..n) {
                        stack.pop()
                    }
                }
                EsilCommand.Operation.LOAD,
                EsilCommand.Operation.LOAD_BYTE,
                EsilCommand.Operation.LOAD_HALF,
                EsilCommand.Operation.LOAD_INT,
                EsilCommand.Operation.LOAD_LONG
                -> {
                    stack.pop()
                    stack.push(StackValue.Unknown)
                }
                EsilCommand.Operation.LOAD_MULTI -> {
                    val n = getValue(stack.pop())!!
                    for (i in 1..n) {
                        stack.push(StackValue.Unknown)
                    }
                }
                EsilCommand.Operation.CLEAR -> stack.clear()

            // not implemented
                EsilCommand.Operation.PICK,
                EsilCommand.Operation.RPICK,
                EsilCommand.Operation.BREAK,
                EsilCommand.Operation.TODO
                -> {
                    state = EsilState.UNKNOWN
                }
            }
        }
    }
}
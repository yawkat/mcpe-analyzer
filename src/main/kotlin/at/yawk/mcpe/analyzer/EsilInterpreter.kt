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
    override fun toString() = "EsilState(${registers.mapValues { "0x" + java.lang.Long.toHexString(it.value) }})"

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

    companion object {
        fun numeric(value: Long?) = if (value == null) Unknown else Numeric(value)
    }
}

interface EsilEnvironment {
    val currentAddress: Long?
    fun load(address: Long, bytes: Int?): Long?
    fun mask(value: Long): Long
    fun translateRegister(name: String): String = name

    object Unknown : EsilEnvironment {
        override val currentAddress: Long? = null
        override fun load(address: Long, bytes: Int?): Long? = null
        override fun mask(value: Long) = value
    }
}

fun interpretEsilInstruction(
        stateBefore: EsilState,
        instruction: List<EsilCommand>,
        environment: EsilEnvironment = EsilEnvironment.Unknown
): EsilState {
    val interpreter = EsilInterpreter(stateBefore, environment)
    instruction.forEach { interpreter.eval(it) }
    return interpreter.state
}

private class EsilInterpreter(var state: EsilState, val environment: EsilEnvironment) {
    val stack = ArrayDeque<StackValue>()

    fun getValue(stackValue: StackValue): Long? = when (stackValue) {
        StackValue.Unknown -> null
        is StackValue.Numeric -> stackValue.value
        is StackValue.Register -> state.registers[environment.translateRegister(stackValue.name)]
    }

    fun setRegister(register: String, value: Long?) {
        if (value == null) {
            state = state.copy(registers = state.registers - environment.translateRegister(register))
        } else {
            state = state.copy(registers = state.registers + (environment.translateRegister(register) to value))
        }
    }

    private inline fun binary(op: (Long, Long) -> Long) {
        val left = getValue(stack.pop())
        val right = getValue(stack.pop())
        if (left != null && right != null) {
            push(op(left, right))
        } else {
            push(null)
        }
    }

    private inline fun binaryRegister(op: (Long, Long) -> Long) {
        val reg = stack.pop() as StackValue.Register
        val left = getValue(reg)
        val right = getValue(stack.pop())
        if (left != null && right != null) {
            setRegister(reg.name, op(left, right))
        } else {
            setRegister(reg.name, null)
        }
    }

    private fun push(value: Long?) {
        stack.push(StackValue.numeric(value?.let { environment.mask(it) }))
    }

    fun eval(cmd: EsilCommand) {
        log.trace("{} -> {}", cmd, stack)

        when (cmd) {
            is EsilCommand.Register -> stack.push(StackValue.Register(cmd.name))
            is EsilCommand.Value -> push(cmd.value)
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
                    push(environment.currentAddress)
                }
                EsilCommand.Operation.COMPARE,
                EsilCommand.Operation.LESS_THAN,
                EsilCommand.Operation.LESS_THAN_EQUAL,
                EsilCommand.Operation.GREATER_THAN,
                EsilCommand.Operation.GREATER_THAN_EQUAL
                -> {
                    stack.pop()
                    stack.pop()
                    stack.push(StackValue.Unknown)
                }
                EsilCommand.Operation.ADD -> binary { a, b -> a + b }
                EsilCommand.Operation.SUB -> binary { a, b -> a - b }
                EsilCommand.Operation.OR -> binary { a, b -> a or b }
                EsilCommand.Operation.AND -> binary { a, b -> a and b }
                EsilCommand.Operation.XOR -> binary { a, b -> a xor b }
                EsilCommand.Operation.MUL -> binary { a, b -> a * b }
                EsilCommand.Operation.DIV -> binary { a, b -> a / b }
                EsilCommand.Operation.MOD -> binary { a, b -> a % b }
                EsilCommand.Operation.SHIFT_LEFT -> binary { a, b -> a shl b.toInt() }
                EsilCommand.Operation.SHIFT_RIGHT -> binary { a, b -> a ushr b.toInt() }
                EsilCommand.Operation.ARITHMETIC_SHIFT_RIGHT -> binary { a, b -> a shr b.toInt() }
                EsilCommand.Operation.ROTATE_RIGHT -> binary { a, b -> (a ushr b.toInt()) or (a shl (32 - b.toInt())) }
                EsilCommand.Operation.ROTATE_LEFT -> binary { a, b -> (a shl b.toInt()) or (a ushr (32 - b.toInt())) }

                EsilCommand.Operation.ADD_REGISTER -> binaryRegister { a, b -> a + b }
                EsilCommand.Operation.SUB_REGISTER -> binaryRegister { a, b -> a - b }
                EsilCommand.Operation.OR_REGISTER -> binaryRegister { a, b -> a or b }
                EsilCommand.Operation.AND_REGISTER -> binaryRegister { a, b -> a and b }
                EsilCommand.Operation.XOR_REGISTER -> binaryRegister { a, b -> a xor b }
                EsilCommand.Operation.MUL_REGISTER -> binaryRegister { a, b -> a * b }
                EsilCommand.Operation.DIV_REGISTER -> binaryRegister { a, b -> a / b }
                EsilCommand.Operation.MOD_REGISTER -> binaryRegister { a, b -> a % b }
                EsilCommand.Operation.SHIFT_LEFT_REGISTER -> binaryRegister { a, b -> a shl b.toInt() }
                EsilCommand.Operation.SHIFT_RIGHT_REGISTER -> binaryRegister { a, b -> a ushr b.toInt() }

                EsilCommand.Operation.INC,
                EsilCommand.Operation.DEC,
                EsilCommand.Operation.NEG
                -> {
                    stack.pop()
                    stack.push(StackValue.Unknown)
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
                    push(getValue(stack.pop()))
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
                EsilCommand.Operation.STORE_LONG,
                EsilCommand.Operation.STORE_LONG_LONG -> {
                    stack.pop()
                    stack.pop()
                }
                EsilCommand.Operation.STORE_MULTI -> {
                    stack.pop() // base reg
                    val n = getValue(stack.pop())!! // int
                    for (i in 1..n) {
                        stack.pop() // value
                    }
                }
                EsilCommand.Operation.LOAD,
                EsilCommand.Operation.LOAD_BYTE,
                EsilCommand.Operation.LOAD_HALF,
                EsilCommand.Operation.LOAD_INT,
                EsilCommand.Operation.LOAD_LONG,
                EsilCommand.Operation.LOAD_LONG_LONG
                -> {
                    val location = getValue(stack.pop())
                    if (location == null) {
                        stack.push(StackValue.Unknown)
                    } else {
                        push(environment.load(location, when (cmd) {
                            EsilCommand.Operation.LOAD -> null
                            EsilCommand.Operation.LOAD_BYTE -> 1
                            EsilCommand.Operation.LOAD_HALF -> 2
                            EsilCommand.Operation.LOAD_INT -> 4
                            EsilCommand.Operation.LOAD_LONG -> 8
                            EsilCommand.Operation.LOAD_LONG_LONG -> 16
                            else -> throw AssertionError()
                        }))
                    }
                }
                EsilCommand.Operation.LOAD_MULTI -> {
                    stack.pop() // base reg
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
package at.yawk.mcpe.analyzer

import org.slf4j.LoggerFactory
import java.util.ArrayDeque
import java.util.HashMap
import java.util.HashSet

/**
 * @author yawkat
 */
private val log = LoggerFactory.getLogger(GraphBuilder::class.java)

fun buildFunctionGraph(pipe: R2Pipe, enterCall: (Call) -> Boolean): RegularExpression<Call> {
    val node = GraphBuilder(pipe, enterCall).build()
    val state = nodeToState(node)
    return automatonToRegex(state)
}

interface Call {
    data class Fixed(val address: Long, val registerGuesses: Map<String, Long>) : Call
    object Unknown : Call
}

private class GraphBuilder(val pipe: R2Pipe, val enterCall: (Call) -> Boolean) {
    val registry = HashMap<Long, Node>()

    private fun guessRegisters(esil: List<EsilCommand>, registerGuessesIn: Map<String, Long>): Map<String, Long> {
        var registerGuesses = registerGuessesIn

        val UNKNOWN = Any()
        val stack = ArrayDeque<Any?>()

        fun eval(cmd: EsilCommand) {
            log.trace("{} -> {}", cmd, stack)

            when (cmd) {
                is EsilCommand.Register -> stack.push(cmd)
                is EsilCommand.Value -> stack.push(cmd.value)
                is EsilCommand.Label -> stack.push(UNKNOWN)
                is EsilCommand.Conditional -> {
                    val before = registerGuesses
                    cmd.body.forEach(::eval)
                    val after = registerGuesses
                    // only keep values that are unchanged in the body
                    registerGuesses = before.filter { after[it.key] == it.value }
                }
                is EsilCommand.Operation -> when (cmd) {
                    EsilCommand.Operation.TRAP,
                    EsilCommand.Operation.SYSCALL
                    -> stack.pop()
                    EsilCommand.Operation.CURRENT_ADDRESS -> {
                        stack.push(UNKNOWN)
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
                        stack.push(UNKNOWN)
                    }
                    EsilCommand.Operation.INC,
                    EsilCommand.Operation.DEC,
                    EsilCommand.Operation.NEG
                    -> {
                        stack.pop()
                        stack.push(UNKNOWN)
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
                        val reg = stack.pop() as EsilCommand.Register
                        stack.pop()
                        registerGuesses = registerGuesses.filterKeys { it != reg.name }
                    }
                    EsilCommand.Operation.INC_REGISTER,
                    EsilCommand.Operation.DEC_REGISTER,
                    EsilCommand.Operation.NOT_REGISTER
                    -> {
                        val reg = stack.pop() as EsilCommand.Register
                        registerGuesses = registerGuesses.filterKeys { it != reg.name }
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
                        stack.push(registerGuesses[(stack.pop() as EsilCommand.Register).name])
                    }
                    EsilCommand.Operation.ASSIGN -> {
                        val reg = stack.pop() as EsilCommand.Register
                        val v = stack.pop()
                        val value: Long? = when (v) {
                            is Long -> v
                            is EsilCommand.Register -> registerGuesses[v.name]
                            else -> null
                        }
                        if (value == null) {
                            registerGuesses[reg.name]
                        } else {
                            registerGuesses += reg.name to value
                        }
                    }
                    EsilCommand.Operation.STORE,
                    EsilCommand.Operation.STORE_BYTE,
                    EsilCommand.Operation.STORE_INT,
                    EsilCommand.Operation.STORE_HALF,
                    EsilCommand.Operation.STORE_LONG-> {
                        stack.pop()
                        stack.pop()
                    }
                    EsilCommand.Operation.STORE_MULTI -> {
                        val n = stack.pop() as Long
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
                        stack.push(UNKNOWN)
                    }
                    EsilCommand.Operation.LOAD_MULTI -> {
                        val n = stack.pop() as Long
                        for (i in 1..n) {
                            stack.push(UNKNOWN)
                        }
                    }
                    EsilCommand.Operation.CLEAR -> stack.clear()

                    // not implemented
                    EsilCommand.Operation.PICK,
                    EsilCommand.Operation.RPICK,
                    EsilCommand.Operation.BREAK,
                    EsilCommand.Operation.TODO
                    -> {
                        registerGuesses = emptyMap()
                    }
                }
            }
        }

        esil.forEach(::eval)
        return registerGuesses
    }

    tailrec fun build(n: Node = Node(), registerGuessesIn: Map<String, Long> = emptyMap()): Node {
        val insn = pipe.disassemble()
        registry.putIfAbsent(insn.offset, n)?.let { return it }

        val registerGuesses: Map<String, Long> = try {
            guessRegisters(insn.esil, registerGuessesIn)
        } catch (e: Exception) {
            log.warn("ESIL evaluation failed", e)
            emptyMap()
        }

        when (insn.type) {
            "call", "ucall" -> {
                n.linkedCall = insn.jump?.let { Call.Fixed(it, registerGuesses) } ?: Call.Unknown
                pipe.skip()
                @Suppress("NON_TAIL_RECURSIVE_CALL")
                n.next = listOf(build())
                return n
            }
            "jmp" -> {
                pipe.seek(insn.jump!!.toLong())
                if ((pipe.disassemble().flags ?: emptyList<String>()).any { it.startsWith("sym.") }) {
                    // tail call
                    val call = Call.Fixed(insn.jump.toLong(), registerGuesses)
                    if (!enterCall(call)) {
                        n.linkedCall = call
                        return n
                    }
                }
                return build(n, registerGuesses)
            }
            "cjmp" -> {
                pipe.skip()
                @Suppress("NON_TAIL_RECURSIVE_CALL")
                val normal = build()
                pipe.seek(insn.jump!!.toLong())
                @Suppress("NON_TAIL_RECURSIVE_CALL")
                val jump = build()
                n.next = listOf(normal, jump)
                return n
            }
            "ccall" -> {
                pipe.skip()
                @Suppress("NON_TAIL_RECURSIVE_CALL")
                val normal = build()
                val call = Call.Fixed(insn.jump!!.toLong(), registerGuesses)
                val jump = if (enterCall(call)) {
                    @Suppress("NON_TAIL_RECURSIVE_CALL")
                    val branchStart = build(n)
                    branchStart.depthFirstSearch {
                        if (it.next.isEmpty()) it.next = listOf(normal)
                    }
                    branchStart
                } else {
                    Node(linkedCall = call, next = listOf(normal))
                }
                n.next = listOf(normal, jump)
                return n
            }
            "ret" -> {
                return n
            }

            "rjmp", "ujmp", "mjmp", "ucjmp", "rcall", "icall", "ircall", "uccall",
            "cret"
            -> TODO(insn.type)

            else -> {
                pipe.skip()
                return build(n, registerGuesses)
            }
        }
    }
}

private class Node(
        var linkedCall: Call? = null,
        var next: List<Node> = emptyList()
)

private tailrec fun Node.depthFirstSearch(f: (Node) -> Unit) {
    val next = next
    f(this)
    if (!next.isEmpty()) {
        next.forEachIndexed { i, node ->
            @Suppress("NON_TAIL_RECURSIVE_CALL")
            if (i > 0) node.depthFirstSearch(f)
        }
        next[0].depthFirstSearch(f)
    }
}

private class State<T>(
        val transitions: MutableMap<State<T>, RegularExpression<T>> = HashMap()
)

private fun nodeToState(n: Node): State<Call> {
    val map = HashMap<Node, State<Call>>()

    fun run(n: Node): State<Call> {
        map[n]?.let { return it }
        val origin: State<Call>
        val target: State<Call>
        val linkedCall = n.linkedCall
        if (linkedCall != null) {
            origin = State()
            target = State()
            origin.transitions[target] = RegularExpression.Terminal(linkedCall)
        } else {
            origin = State()
            target = origin
        }
        map[n] = origin
        for (next in n.next) {
            target.transitions[run(next)] = RegularExpression.Concatenate(emptyList())
        }
        return origin
    }

    return run(n)
}

private fun <T> automatonToRegex(start: State<T>): RegularExpression<T> {
    val allStates = HashSet<State<T>>()

    run {
        val addQueue = ArrayDeque<State<T>>()
        addQueue.push(start)
        while (true) {
            val next = addQueue.poll() ?: break
            if (allStates.add(next)) {
                addQueue.addAll(next.transitions.keys)
            }
        }
    }

    fun eliminate(state: State<T>) {
        allStates.remove(state)
        val selfTransition = state.transitions.remove(state)?.zeroOrMore() ?: RegularExpression.empty<T>()
        for (from in allStates) {
            val transitionToEliminate = from.transitions.remove(state) ?: continue
            for ((to, tail) in state.transitions) {
                val added = transitionToEliminate concat selfTransition concat tail
                val old = from.transitions[to]
                if (old == null) from.transitions[to] = added
                else from.transitions[to] = added or old
            }
        }
    }

    while (true) {
        val next = allStates.firstOrNull { it != start && !it.transitions.isEmpty() } ?: break
        eliminate(next)
    }

    if (allStates.size == 1) {
        return start.transitions[start]?.zeroOrMore() ?: RegularExpression.empty()
    }

    val end = allStates.filter { it != start }
    var endRegex = end.mapNotNull { start.transitions[it] }
    val inStartTransition = start.transitions[start]
    if (inStartTransition != null) {
        endRegex = endRegex.map { inStartTransition.zeroOrMore() concat it }
    }
    return RegularExpression.Or(endRegex.toSet())
}


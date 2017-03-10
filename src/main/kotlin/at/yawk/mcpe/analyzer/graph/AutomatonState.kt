package at.yawk.mcpe.analyzer.graph

import at.yawk.mcpe.analyzer.RegularExpression
import at.yawk.mcpe.analyzer.concat
import at.yawk.mcpe.analyzer.or
import at.yawk.mcpe.analyzer.zeroOrMore
import java.util.ArrayDeque
import java.util.HashSet

/**
 * @author yawkat
 */
class AutomatonState<T>(
        var acceptingState: Boolean,
        var transitions: MutableMap<AutomatonState<T>, RegularExpression<T>> = HashMap()
) {
    companion object {
        fun <K, T> build(start: K, f: FluentBuilder<K, T>.() -> Unit): AutomatonState<T> {
            val builder = FluentBuilder<K, T>()
            builder.f()
            return builder.state(start)
        }

        class FluentBuilder<K, T> internal constructor() {
            private val states = HashMap<K, AutomatonState<T>>()

            fun state(key: K) = states.getOrPut(key) { AutomatonState(acceptingState = false) }

            infix fun K.on(transition: T) = this on RegularExpression.Terminal(transition)
            infix fun K.on(transition: RegularExpression<T>) = TransitionBuilder(this, transition)

            fun accept(key: K) {
                state(key).acceptingState = true
            }

            inner class TransitionBuilder internal constructor(private val source: K, private val transition: RegularExpression<T>) {
                infix fun goto(to: K) {
                    state(source).transitions[state(to)] = transition
                }
            }
        }
    }

    fun destructiveToRegex(): RegularExpression<T> {
        val allStates = HashSet<AutomatonState<T>>()

        // collect all states
        run {
            val addQueue = ArrayDeque<AutomatonState<T>>()
            addQueue.push(this)
            while (true) {
                val next = addQueue.poll() ?: break
                if (allStates.add(next)) {
                    addQueue.addAll(next.transitions.keys)
                }
            }
        }

        // amend accepting states with outbound transitions with an auxiliary state
        run {
            val extraAcceptingState = AutomatonState<T>(acceptingState = true)
            for (state in allStates) {
                if (state.acceptingState && !state.transitions.isEmpty()) {
                    state.transitions[extraAcceptingState] = RegularExpression.empty()
                    state.acceptingState = false
                }
            }
            allStates.add(extraAcceptingState)
        }

        // invariant: accepting states have no outbound transitions.

        fun eliminate(state: AutomatonState<T>) {
            allStates.remove(state)
            val selfTransition = state.transitions.remove(state)?.zeroOrMore() ?: RegularExpression.empty<T>()
            for (from in allStates) {
                val transitionToEliminate = from.transitions.remove(state) ?: continue
                for ((to, tail) in state.transitions) {
                    val added = transitionToEliminate concat selfTransition concat tail
                    val old = from.transitions[to] ?: RegularExpression.nothing()
                    from.transitions[to] = added or old
                }
            }
        }

        while (true) {
            val next = allStates.firstOrNull { it != this && !it.acceptingState } ?: break
            eliminate(next)
        }

        val inStartTransition = transitions[this]?.zeroOrMore() ?: RegularExpression.empty<T>()

        if (acceptingState) {
            // because of invariant we can have no outbound transitions
            assert(transitions.isEmpty())
            return inStartTransition
        }

        val acceptRegex = allStates
                .filter { it.acceptingState }
                .mapNotNull { transitions[it] }
                .map { inStartTransition concat it }
                .toSet()

        return RegularExpression.Or(acceptRegex)
    }
}